/**
 * AggregatorClient — HTTP + WebSocket client for the 0x01 aggregator REST API.
 *
 * The aggregator is a separate service from the node. It tracks reputation,
 * agent discovery, and activity across the mesh. This client is read-mostly.
 *
 * Public aggregator: https://agg.0x01.world
 */
import type { AgentRecord, AgentProfile, ActivityEvent, NetworkStats, HostingNode, AgentsParams, ActivityParams } from './types.js';
export interface AggregatorClientOptions {
    /** Aggregator base URL, e.g. "https://agg.0x01.world" */
    url: string;
    /** API key for gated read endpoints (reputation, leaderboard, etc.) */
    apiKey?: string;
}
export declare class AggregatorClient {
    private readonly baseUrl;
    private readonly apiKey;
    constructor(opts: AggregatorClientOptions);
    private headers;
    private get;
    /** List agents on the mesh, optionally filtered by country or capabilities. */
    agents(params?: AgentsParams): Promise<AgentRecord[]>;
    /** Get full profile for a single agent (reputation, capabilities, recent disputes). */
    agentProfile(agentId: string): Promise<AgentProfile>;
    /** Reverse-lookup: get all agents registered to a wallet address. */
    agentsByOwner(wallet: string): Promise<AgentRecord[]>;
    /** Get the owner record for an agent (unclaimed / pending / claimed). */
    agentOwner(agentId: string): Promise<unknown>;
    /** Detailed reputation snapshot. Requires API key. */
    reputation(agentId: string): Promise<unknown>;
    /**
     * Fetch recent activity events (JOIN, FEEDBACK, DISPUTE, VERDICT).
     * Use `params.before` for cursor pagination (pass last seen `id`).
     */
    activity(params?: ActivityParams): Promise<ActivityEvent[]>;
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
    watchActivity(handler: (event: ActivityEvent) => void): () => void;
    /** High-level stats: total agents, total interactions, uptime. */
    networkStats(): Promise<NetworkStats>;
    /** List currently active hosting nodes (seen in last 120s). */
    hostingNodes(): Promise<HostingNode[]>;
    /** Download a blob by CID. Returns raw Response for streaming. */
    downloadBlob(cid: string): Promise<Response>;
}
//# sourceMappingURL=AggregatorClient.d.ts.map