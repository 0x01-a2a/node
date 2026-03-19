"use strict";
/**
 * HostedFleet — manages a pool of hosted agents on a single node.
 *
 * Hosted agents are sub-identities created by the node with their own
 * Ed25519 keypairs. Apps use them to participate in the mesh without
 * running their own node processes. The fleet handles:
 *
 * - Registration + token caching (survives app restarts via TokenStore)
 * - Per-agent inbox WebSocket with auto-reconnect
 * - Conversation thread tracking (both inbound and outbound)
 * - Re-registration when node restarts (token invalidation)
 *
 * For multi-node deployments (distributing agents across different nodes),
 * see `MultiFleet`.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MultiFleet = exports.HostedFleet = exports.HostedAgent = exports.Conversation = void 0;
const ws_1 = __importDefault(require("ws"));
const codec_js_1 = require("./codec.js");
// ============================================================================
// Conversation
// ============================================================================
/** A tracked message thread between agents. */
class Conversation {
    constructor(id) {
        this.messages = [];
        this.participants = new Set();
        this.id = id;
    }
    /** @internal */
    _push(env) {
        this.messages.push(env);
        this.participants.add(env.sender);
        this.participants.add(env.recipient);
    }
    lastMessage() {
        return this.messages[this.messages.length - 1];
    }
    history() {
        return [...this.messages];
    }
}
exports.Conversation = Conversation;
/** A single hosted agent identity on a node. */
class HostedAgent {
    constructor(opts) {
        this.conversations = new Map();
        this.handlers = new Map();
        this.ws = null;
        this.wsClosed = false;
        this.wsReconnectTimer = null;
        this.agentId = opts.agentId;
        this.token = opts.token;
        this.nodeUrl = opts.nodeUrl.replace(/\/$/, '');
    }
    // ── Subscribe ─────────────────────────────────────────────────────────────
    /** Register a message handler. Use '*' to catch all types. Returns `this` for chaining. */
    on(msgType, handler) {
        const set = this.handlers.get(msgType) ?? new Set();
        set.add(handler);
        this.handlers.set(msgType, set);
        return this;
    }
    off(msgType, handler) {
        this.handlers.get(msgType)?.delete(handler);
        return this;
    }
    /**
     * Start listening to the inbox WebSocket.
     * Call this once after registering all handlers.
     * Returns an unsubscribe/cleanup function.
     */
    listen() {
        this.wsClosed = false;
        this._connectWs();
        return () => this.dispose();
    }
    _connectWs() {
        if (this.wsClosed)
            return;
        const wsBase = this.nodeUrl.replace(/^http/, 'ws');
        const url = `${wsBase}/ws/hosted/inbox?token=${this.token}`;
        this.ws = new ws_1.default(url);
        this.ws.on('message', (data) => {
            try {
                const env = JSON.parse(data.toString());
                const conv = this._getOrCreateConv(env.conversation_id);
                conv._push(env);
                this._emit(env.msg_type, env, conv);
                this._emit('*', env, conv);
            }
            catch (e) {
                console.error('[HostedAgent] failed to parse inbound message:', e);
            }
        });
        this.ws.on('close', () => {
            if (!this.wsClosed) {
                this.wsReconnectTimer = setTimeout(() => this._connectWs(), 3000);
            }
        });
        this.ws.on('error', (e) => {
            console.error('[HostedAgent] WebSocket error:', e);
        });
    }
    _emit(type, env, conv) {
        this.handlers.get(type)?.forEach((h) => {
            try {
                h(env, conv);
            }
            catch (e) {
                console.error(`[HostedAgent] handler error:`, e);
            }
        });
    }
    _getOrCreateConv(id) {
        if (!this.conversations.has(id))
            this.conversations.set(id, new Conversation(id));
        return this.conversations.get(id);
    }
    // ── Conversation access ───────────────────────────────────────────────────
    /**
     * Get a conversation by ID.
     *
     * Available immediately after any outbound send (propose/counter/accept/send)
     * that uses or generates a conversation_id — not just after the first inbound
     * reply arrives.
     */
    conversation(id) {
        return this.conversations.get(id);
    }
    allConversations() {
        return Array.from(this.conversations.values());
    }
    // ── HTTP helpers ──────────────────────────────────────────────────────────
    async _post(path, body) {
        const res = await fetch(`${this.nodeUrl}${path}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${this.token}`,
            },
            body: JSON.stringify(body),
        });
        if (!res.ok)
            throw new Error(`POST ${path} → ${res.status}: ${await res.text()}`);
        if (res.status === 204)
            return undefined;
        return res.json();
    }
    // ── Send ──────────────────────────────────────────────────────────────────
    /**
     * Send a raw message to a recipient (or broadcast if recipient omitted).
     * Pre-creates a Conversation so `agent.conversation(conversationId)` is
     * available immediately after this call.
     */
    async send(params) {
        const conversation_id = params.conversationId ?? (0, codec_js_1.newConversationId)();
        await this._post('/hosted/send', {
            msg_type: params.msgType,
            recipient: params.recipient ?? null,
            conversation_id,
            payload_hex: Buffer.from(params.payload).toString('hex'),
        });
        this._getOrCreateConv(conversation_id);
        return { conversation_id };
    }
    // ── Negotiate shortcuts ───────────────────────────────────────────────────
    /**
     * Propose a deal to a recipient.
     * The returned conversation_id is immediately available via `agent.conversation(id)`.
     *
     * ```ts
     * const { conversation_id } = await agent.propose({
     *   recipient: otherAgent.agentId,
     *   message: 'Build a REST API for our product',
     *   amountMicro: 10_000_000n, // 10 USDC
     * })
     * // conversation is already tracked:
     * console.log(agent.conversation(conversation_id))
     * ```
     */
    async propose(params) {
        const result = await this._post('/hosted/negotiate/propose', {
            recipient: params.recipient,
            conversation_id: params.conversationId ?? null,
            amount_usdc_micro: params.amountMicro !== undefined ? Number(params.amountMicro) : 0,
            max_rounds: params.maxRounds ?? 2,
            message: params.message,
        });
        this._getOrCreateConv(result.conversation_id);
        return result;
    }
    async counter(params) {
        const result = await this._post('/hosted/negotiate/counter', {
            recipient: params.recipient,
            conversation_id: params.conversationId,
            amount_usdc_micro: Number(params.amountMicro),
            round: params.round,
            max_rounds: params.maxRounds ?? null,
            message: params.message ?? null,
        });
        this._getOrCreateConv(result.conversation_id);
        return result;
    }
    async accept(params) {
        const result = await this._post('/hosted/negotiate/accept', {
            recipient: params.recipient,
            conversation_id: params.conversationId,
            amount_usdc_micro: Number(params.amountMicro),
            message: params.message ?? null,
        });
        this._getOrCreateConv(result.conversation_id);
        return result;
    }
    // ── Lifecycle ─────────────────────────────────────────────────────────────
    async ping() {
        try {
            const res = await fetch(`${this.nodeUrl}/hosted/ping`, {
                headers: { Authorization: `Bearer ${this.token}` },
            });
            return res.ok;
        }
        catch {
            return false;
        }
    }
    dispose() {
        this.wsClosed = true;
        if (this.wsReconnectTimer)
            clearTimeout(this.wsReconnectTimer);
        this.ws?.close();
    }
}
exports.HostedAgent = HostedAgent;
/**
 * Manages a named pool of hosted agents on a single node.
 *
 * ```ts
 * const fleet = new HostedFleet({ nodeUrl: 'http://localhost:9090', store })
 * const ceo = await fleet.register('ceo')
 * const dev = await fleet.register('dev')
 *
 * ceo.on('PROPOSE', async (env, conv) => {
 *   const p = decodeProposePayload(env.payload_b64)
 *   if (!p) return
 *   await ceo.accept({ recipient: env.sender, conversationId: env.conversation_id, amountMicro: p.amount_micro })
 * }).listen()
 *
 * // propose() returns a conversation_id that is immediately trackable
 * const { conversation_id } = await ceo.propose({
 *   recipient: dev.agentId,
 *   message: 'Build a REST API',
 *   amountMicro: 10_000_000n,
 * })
 * console.log(ceo.conversation(conversation_id)) // already exists
 * ```
 */
class HostedFleet {
    constructor(opts) {
        this.agents = new Map();
        this.nodeUrl = opts.nodeUrl.replace(/\/$/, '');
        this.store = opts.store;
    }
    /**
     * Register a named hosted agent.
     * Reuses a cached token if valid (ping-validates first).
     * Re-registers automatically on token expiry or node restart.
     */
    async register(name) {
        const cached = await this.store?.get(name);
        if (cached) {
            const agent = new HostedAgent({ nodeUrl: this.nodeUrl, ...cached });
            if (await agent.ping()) {
                this.agents.set(name, agent);
                return agent;
            }
            await this.store?.delete(name);
        }
        const res = await fetch(`${this.nodeUrl}/hosted/register`, { method: 'POST' });
        if (!res.ok)
            throw new Error(`HostedFleet.register: /hosted/register → ${res.status}`);
        const { agent_id, token } = await res.json();
        await this.store?.set(name, { agentId: agent_id, token });
        const agent = new HostedAgent({ nodeUrl: this.nodeUrl, agentId: agent_id, token });
        this.agents.set(name, agent);
        return agent;
    }
    get(name) {
        return this.agents.get(name);
    }
    all() {
        return Array.from(this.agents.values());
    }
    dispose() {
        for (const agent of this.agents.values())
            agent.dispose();
        this.agents.clear();
    }
}
exports.HostedFleet = HostedFleet;
/**
 * Manages hosted agents distributed across multiple nodes.
 *
 * Use this when different agent roles run on different zerox1-node instances —
 * for example, public-facing agents on one node and internal agents on another.
 *
 * ```ts
 * const multi = new MultiFleet({
 *   nodes: {
 *     us: 'http://us-node:9090',
 *     eu: 'http://eu-node:9090',
 *   },
 *   store,
 * })
 *
 * const ceo    = await multi.register('ceo',    'us')
 * const dev    = await multi.register('dev',    'us')
 * const sales  = await multi.register('sales',  'eu')
 * const analyst = await multi.register('analyst', 'eu')
 *
 * // All agents work exactly like single-fleet HostedAgent instances
 * ceo.on('PROPOSE', handler).listen()
 * ```
 */
class MultiFleet {
    constructor(opts) {
        this.fleets = new Map();
        this.agents = new Map();
        const scopedStore = (nodeName) => {
            if (!opts.store)
                return undefined;
            return {
                get: (key) => opts.store.get(`${nodeName}:${key}`),
                set: (key, val) => opts.store.set(`${nodeName}:${key}`, val),
                delete: (key) => opts.store.delete(`${nodeName}:${key}`),
            };
        };
        for (const [name, url] of Object.entries(opts.nodes)) {
            this.fleets.set(name, new HostedFleet({ nodeUrl: url, store: scopedStore(name) }));
        }
    }
    /**
     * Register a named agent on a specific node.
     * @param agentName - Unique name for this agent (e.g. 'ceo', 'dev')
     * @param nodeName  - Which node to register on (must be in `nodes` config)
     */
    async register(agentName, nodeName) {
        const fleet = this.fleets.get(nodeName);
        if (!fleet)
            throw new Error(`MultiFleet: unknown node "${nodeName}"`);
        const agent = await fleet.register(agentName);
        this.agents.set(agentName, agent);
        return agent;
    }
    get(agentName) {
        return this.agents.get(agentName);
    }
    all() {
        return Array.from(this.agents.values());
    }
    fleet(nodeName) {
        return this.fleets.get(nodeName);
    }
    dispose() {
        for (const fleet of this.fleets.values())
            fleet.dispose();
        this.agents.clear();
    }
}
exports.MultiFleet = MultiFleet;
//# sourceMappingURL=HostedFleet.js.map