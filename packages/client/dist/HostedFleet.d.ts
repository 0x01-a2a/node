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
import type { InboundEnvelope, MsgType } from './types.js';
import type { ProposeParams, CounterParams, AcceptParams } from './NodeClient.js';
/** A tracked message thread between agents. */
export declare class Conversation {
    readonly id: string;
    readonly messages: InboundEnvelope[];
    readonly participants: Set<string>;
    constructor(id: string);
    /** @internal */
    _push(env: InboundEnvelope): void;
    lastMessage(): InboundEnvelope | undefined;
    history(): InboundEnvelope[];
}
type Handler = (env: InboundEnvelope, conv: Conversation) => void;
export interface HostedAgentOptions {
    nodeUrl: string;
    agentId: string;
    token: string;
}
export interface HostedSendParams {
    msgType: MsgType;
    recipient?: string;
    conversationId?: string;
    payload: Uint8Array;
}
/** A single hosted agent identity on a node. */
export declare class HostedAgent {
    readonly agentId: string;
    readonly token: string;
    private readonly nodeUrl;
    private readonly conversations;
    private readonly handlers;
    private ws;
    private wsClosed;
    private wsReconnectTimer;
    constructor(opts: HostedAgentOptions);
    /** Register a message handler. Use '*' to catch all types. Returns `this` for chaining. */
    on(msgType: MsgType | '*', handler: Handler): this;
    off(msgType: MsgType | '*', handler: Handler): this;
    /**
     * Start listening to the inbox WebSocket.
     * Call this once after registering all handlers.
     * Returns an unsubscribe/cleanup function.
     */
    listen(): () => void;
    private _connectWs;
    private _emit;
    private _getOrCreateConv;
    /**
     * Get a conversation by ID.
     *
     * Available immediately after any outbound send (propose/counter/accept/send)
     * that uses or generates a conversation_id — not just after the first inbound
     * reply arrives.
     */
    conversation(id: string): Conversation | undefined;
    allConversations(): Conversation[];
    private _post;
    /**
     * Send a raw message to a recipient (or broadcast if recipient omitted).
     * Pre-creates a Conversation so `agent.conversation(conversationId)` is
     * available immediately after this call.
     */
    send(params: HostedSendParams): Promise<{
        conversation_id: string;
    }>;
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
    propose(params: ProposeParams): Promise<{
        conversation_id: string;
    }>;
    counter(params: CounterParams): Promise<{
        conversation_id: string;
    }>;
    accept(params: AcceptParams): Promise<{
        conversation_id: string;
    }>;
    ping(): Promise<boolean>;
    dispose(): void;
}
export interface TokenStore {
    get(key: string): Promise<{
        agentId: string;
        token: string;
    } | undefined>;
    set(key: string, value: {
        agentId: string;
        token: string;
    }): Promise<void>;
    delete(key: string): Promise<void>;
}
export interface HostedFleetOptions {
    /** Node API base URL */
    nodeUrl: string;
    /**
     * Optional token store — implement to persist tokens across restarts.
     * If omitted, tokens are kept in memory only (lost on process exit).
     *
     * Example SQLite implementation:
     * ```ts
     * const store: TokenStore = {
     *   get: async (key) => db.get('SELECT agent_id, token FROM identities WHERE role = ?', key)
     *     .then(r => r ? { agentId: r.agent_id, token: r.token } : undefined),
     *   set: async (key, { agentId, token }) =>
     *     db.run('INSERT OR REPLACE INTO identities (role, agent_id, token) VALUES (?, ?, ?)', key, agentId, token),
     *   delete: async (key) => db.run('DELETE FROM identities WHERE role = ?', key),
     * }
     * ```
     */
    store?: TokenStore;
}
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
export declare class HostedFleet {
    private readonly nodeUrl;
    private readonly store?;
    private readonly agents;
    constructor(opts: HostedFleetOptions);
    /**
     * Register a named hosted agent.
     * Reuses a cached token if valid (ping-validates first).
     * Re-registers automatically on token expiry or node restart.
     */
    register(name: string): Promise<HostedAgent>;
    get(name: string): HostedAgent | undefined;
    all(): HostedAgent[];
    dispose(): void;
}
export interface MultiFleetOptions {
    /**
     * Named node URLs. Each key is a node name; the value is its API base URL.
     *
     * ```ts
     * nodes: {
     *   primary:   'http://node1.corp.com:9090',
     *   secondary: 'http://node2.corp.com:9090',
     * }
     * ```
     */
    nodes: Record<string, string>;
    /** Shared token store. Keys are scoped as `<nodeName>:<agentName>`. */
    store?: TokenStore;
}
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
export declare class MultiFleet {
    private readonly fleets;
    private readonly agents;
    constructor(opts: MultiFleetOptions);
    /**
     * Register a named agent on a specific node.
     * @param agentName - Unique name for this agent (e.g. 'ceo', 'dev')
     * @param nodeName  - Which node to register on (must be in `nodes` config)
     */
    register(agentName: string, nodeName: string): Promise<HostedAgent>;
    get(agentName: string): HostedAgent | undefined;
    all(): HostedAgent[];
    fleet(nodeName: string): HostedFleet | undefined;
    dispose(): void;
}
export {};
//# sourceMappingURL=HostedFleet.d.ts.map