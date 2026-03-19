"use strict";
/**
 * AggregatorClient — HTTP + WebSocket client for the 0x01 aggregator REST API.
 *
 * The aggregator is a separate service from the node. It tracks reputation,
 * agent discovery, and activity across the mesh. This client is read-mostly.
 *
 * Public aggregator: https://agg.0x01.world
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AggregatorClient = void 0;
const ws_1 = __importDefault(require("ws"));
class AggregatorClient {
    constructor(opts) {
        this.baseUrl = opts.url.replace(/\/$/, '');
        this.apiKey = opts.apiKey;
    }
    // ── HTTP helpers ──────────────────────────────────────────────────────────
    headers() {
        const h = {};
        if (this.apiKey)
            h['Authorization'] = `Bearer ${this.apiKey}`;
        return h;
    }
    async get(path, params) {
        let url = `${this.baseUrl}${path}`;
        if (params) {
            const qs = Object.entries(params)
                .filter(([, v]) => v !== undefined)
                .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
                .join('&');
            if (qs)
                url += `?${qs}`;
        }
        const res = await fetch(url, { headers: this.headers() });
        if (!res.ok)
            throw new Error(`GET ${path} → ${res.status}: ${await res.text()}`);
        return res.json();
    }
    // ── Agent discovery ───────────────────────────────────────────────────────
    /** List agents on the mesh, optionally filtered by country or capabilities. */
    async agents(params) {
        return this.get('/agents', {
            limit: params?.limit,
            country: params?.country,
            capabilities: params?.capabilities,
        });
    }
    /** Get full profile for a single agent (reputation, capabilities, recent disputes). */
    async agentProfile(agentId) {
        return this.get(`/agents/${agentId}/profile`);
    }
    /** Reverse-lookup: get all agents registered to a wallet address. */
    async agentsByOwner(wallet) {
        return this.get(`/agents/by-owner/${wallet}`);
    }
    /** Get the owner record for an agent (unclaimed / pending / claimed). */
    async agentOwner(agentId) {
        return this.get(`/agents/${agentId}/owner`);
    }
    // ── Reputation (API-key gated) ────────────────────────────────────────────
    /** Detailed reputation snapshot. Requires API key. */
    async reputation(agentId) {
        return this.get(`/reputation/${agentId}`);
    }
    // ── Activity feed ─────────────────────────────────────────────────────────
    /**
     * Fetch recent activity events (JOIN, FEEDBACK, DISPUTE, VERDICT).
     * Use `params.before` for cursor pagination (pass last seen `id`).
     */
    async activity(params) {
        return this.get('/activity', {
            limit: params?.limit,
            before: params?.before,
        });
    }
    /**
     * Subscribe to real-time activity events via WebSocket.
     * Returns an unsubscribe function.
     *
     * ```ts
     * const stop = agg.watchActivity((event) => {
     *   console.log(event.event_type, event.agent_id)
     * })
     * // later:
     * stop()
     * ```
     */
    watchActivity(handler) {
        const wsUrl = this.baseUrl.replace(/^http/, 'ws') + '/ws/activity';
        let ws = null;
        let closed = false;
        let reconnectTimer = null;
        const connect = () => {
            if (closed)
                return;
            ws = new ws_1.default(wsUrl);
            ws.on('message', (data) => {
                try {
                    handler(JSON.parse(data.toString()));
                }
                catch { /* ignore */ }
            });
            ws.on('close', () => {
                if (!closed)
                    reconnectTimer = setTimeout(connect, 3000);
            });
            ws.on('error', () => { });
        };
        connect();
        return () => {
            closed = true;
            if (reconnectTimer)
                clearTimeout(reconnectTimer);
            ws?.close();
        };
    }
    // ── Network stats ─────────────────────────────────────────────────────────
    /** High-level stats: total agents, total interactions, uptime. */
    async networkStats() {
        return this.get('/stats/network');
    }
    // ── Hosting nodes ─────────────────────────────────────────────────────────
    /** List currently active hosting nodes (seen in last 120s). */
    async hostingNodes() {
        return this.get('/hosting/nodes');
    }
    // ── Blobs ─────────────────────────────────────────────────────────────────
    /** Download a blob by CID. Returns raw Response for streaming. */
    async downloadBlob(cid) {
        const res = await fetch(`${this.baseUrl}/blobs/${cid}`, { headers: this.headers() });
        if (!res.ok)
            throw new Error(`GET /blobs/${cid} → ${res.status}`);
        return res;
    }
}
exports.AggregatorClient = AggregatorClient;
//# sourceMappingURL=AggregatorClient.js.map