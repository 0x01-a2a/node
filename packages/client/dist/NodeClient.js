"use strict";
/**
 * NodeClient — HTTP + WebSocket client for the zerox1-node REST API.
 *
 * Works with both local nodes (127.0.0.1:9090) and remote nodes.
 * Does not manage the node binary — use @zerox1/sdk for that.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NodeClient = void 0;
const ws_1 = __importDefault(require("ws"));
const codec_js_1 = require("./codec.js");
class NodeClient {
    constructor(opts) {
        this.baseUrl = opts.url.replace(/\/$/, '');
        this.secret = opts.secret;
    }
    // ── HTTP helpers ──────────────────────────────────────────────────────────
    headers(extra) {
        const h = { 'Content-Type': 'application/json' };
        if (this.secret)
            h['Authorization'] = `Bearer ${this.secret}`;
        return { ...h, ...extra };
    }
    async get(path) {
        const res = await fetch(`${this.baseUrl}${path}`, { headers: this.headers() });
        if (!res.ok)
            throw new Error(`GET ${path} → ${res.status}: ${await res.text()}`);
        return res.json();
    }
    async post(path, body) {
        const res = await fetch(`${this.baseUrl}${path}`, {
            method: 'POST',
            headers: this.headers(),
            body: JSON.stringify(body),
        });
        if (!res.ok)
            throw new Error(`POST ${path} → ${res.status}: ${await res.text()}`);
        return res.json();
    }
    // ── Identity & status ─────────────────────────────────────────────────────
    async identity() {
        return this.get('/identity');
    }
    async peers() {
        return this.get('/peers');
    }
    async reputation(agentId) {
        return this.get(`/reputation/${agentId}`);
    }
    // ── Send ──────────────────────────────────────────────────────────────────
    async send(params) {
        return this.post('/envelopes/send', {
            msg_type: params.msgType,
            recipient: params.recipient ?? null,
            conversation_id: params.conversationId ?? (0, codec_js_1.newConversationId)(),
            payload_b64: (0, codec_js_1.bytesToBase64)(params.payload),
        });
    }
    /**
     * Publish a BROADCAST envelope on gossipsub — no recipient, delivered to all
     * subscribers of the named topic.
     *
     * ```ts
     * await client.broadcast({
     *   payload: {
     *     topic: 'radio:defi-daily',
     *     title: 'Solana DeFi Digest — Ep 42',
     *     tags: ['defi', 'solana', 'en'],
     *     format: 'audio',
     *     content_b64: '<base64 mp3 chunk>',
     *     content_type: 'audio/mpeg',
     *     chunk_index: 0,
     *     duration_ms: 5000,
     *     price_per_epoch_micro: 10_000, // 0.01 USDC
     *   },
     * })
     * ```
     */
    async broadcast(params) {
        return this.send({
            msgType: 'BROADCAST',
            conversationId: params.conversationId,
            payload: (0, codec_js_1.encodeBroadcastPayload)(params.payload),
        });
    }
    // ── Negotiate shortcuts ───────────────────────────────────────────────────
    async propose(params) {
        return this.post('/negotiate/propose', {
            recipient: params.recipient,
            conversation_id: params.conversationId ?? null,
            amount_usdc_micro: params.amountMicro !== undefined ? Number(params.amountMicro) : 0,
            max_rounds: params.maxRounds ?? 2,
            message: params.message,
        });
    }
    async counter(params) {
        return this.post('/negotiate/counter', {
            recipient: params.recipient,
            conversation_id: params.conversationId,
            amount_usdc_micro: Number(params.amountMicro),
            round: params.round,
            max_rounds: params.maxRounds ?? null,
            message: params.message ?? null,
        });
    }
    async accept(params) {
        return this.post('/negotiate/accept', {
            recipient: params.recipient,
            conversation_id: params.conversationId,
            amount_usdc_micro: Number(params.amountMicro),
            message: params.message ?? null,
        });
    }
    // ── Skills ────────────────────────────────────────────────────────────────
    async listSkills() {
        return this.get('/skill/list');
    }
    async installSkill(url, name) {
        await this.post('/skill/install-url', { url, name: name ?? null });
    }
    async removeSkill(name) {
        await this.post('/skill/remove', { name });
    }
    // ── WebSocket subscriptions ───────────────────────────────────────────────
    /**
     * Subscribe to the local agent inbox.
     * Returns an unsubscribe function.
     */
    inbox(handler) {
        return this._wsSubscribe('/ws/inbox', handler);
    }
    /**
     * Subscribe to node events (peer connect/disconnect, etc.).
     * Returns an unsubscribe function.
     */
    events(handler) {
        return this._wsSubscribe('/ws/events', handler);
    }
    _wsSubscribe(path, handler) {
        const wsUrl = this.baseUrl.replace(/^http/, 'ws') + path;
        const params = this.secret ? `?token=${this.secret}` : '';
        let ws = null;
        let closed = false;
        let reconnectTimer = null;
        const connect = () => {
            if (closed)
                return;
            ws = new ws_1.default(`${wsUrl}${params}`);
            ws.on('message', (data) => {
                try {
                    handler(JSON.parse(data.toString()));
                }
                catch (e) {
                    console.error('[NodeClient] failed to parse message:', e);
                }
            });
            ws.on('close', () => {
                if (!closed)
                    reconnectTimer = setTimeout(connect, 3000);
            });
            ws.on('error', (e) => {
                console.error('[NodeClient] WebSocket error:', e);
            });
        };
        connect();
        return () => {
            closed = true;
            if (reconnectTimer)
                clearTimeout(reconnectTimer);
            ws?.close();
        };
    }
}
exports.NodeClient = NodeClient;
//# sourceMappingURL=NodeClient.js.map