/**
 * Public mesh type extensions — re-exports @zerox1/core base types and adds
 * public-mesh specific fields (geo, latency, system message types).
 */
import type { NegotiationMsgType, InboundEnvelope as CoreInboundEnvelope, AgentRecord as CoreAgentRecord, AgentsParams as CoreAgentsParams, NotarizeBidPayload } from '@zerox1/core';
/** Full public mesh message type — negotiation + system messages. */
export type MsgType = NegotiationMsgType | 'VERDICT' | 'ADVERTISE' | 'DISCOVER' | 'BEACON' | 'NOTARIZE_BID' | 'NOTARIZE_ASSIGN' | 'BROADCAST';
/**
 * Public mesh inbound envelope.
 *
 * `slot` is always present — it is the Solana slot at which the node
 * processed the message. Use it for ordering or deduplication.
 *
 * `notarize_bid` is pre-decoded by the node and only present on
 * NOTARIZE_BID messages. For all other types it is undefined.
 */
export type InboundEnvelope = CoreInboundEnvelope<MsgType> & {
    /** Solana slot — always present on public mesh envelopes. */
    slot: number;
    /** Pre-decoded notarize bid — only present on NOTARIZE_BID messages. */
    notarize_bid?: NotarizeBidPayload;
};
/** Agent record with geo and latency fields from the public mesh. */
export interface AgentRecord extends CoreAgentRecord {
    country?: string;
    city?: string;
    latency?: Record<string, number>;
    geo_consistent?: boolean;
}
export interface AgentProfile extends AgentRecord {
    total_tasks?: number;
    total_disputes?: number;
    last_active?: number;
}
/** Reputation snapshot with geo consistency data for the public mesh. */
export interface ReputationSnapshot {
    agent_id: string;
    reliability: number;
    cooperation: number;
    total_tasks: number;
    total_disputes: number;
    last_active_epoch?: number;
    country?: string;
    city?: string;
    latency?: Record<string, number>;
    geo_consistent?: boolean;
}
/** Agent discovery params with geo and capability filtering. */
export interface AgentsParams extends CoreAgentsParams {
    country?: string;
    capabilities?: string;
}
/**
 * Payload for a BROADCAST envelope — one-to-many gossipsub publish.
 *
 * A BROADCAST carries a named `topic` that listener agents subscribe to.
 * Content can be a streaming audio chunk, a text post, or arbitrary data.
 * The envelope has no `recipient` field — it is delivered to all subscribers.
 *
 * Typical radio use:
 * - Producer agent publishes successive chunks with `chunk_index` counting up.
 * - Listener agents match on `topic` + `tags` and relay audio to the app.
 * - `price_per_epoch_micro` signals the subscription cost; payment is handled
 *   out-of-band via a standard PROPOSE/ACCEPT negotiation.
 */
export interface BroadcastPayload {
    /** Named gossipsub topic, e.g. "radio:defi-daily" or "data:sol-price". */
    topic: string;
    /** Human-readable title for this episode / content item. */
    title: string;
    /** Discovery tags: capability names, language codes, genre, etc. */
    tags: string[];
    /** Content format. */
    format: 'audio' | 'text' | 'data';
    /** Base64-encoded content chunk. Omit for metadata-only announces. */
    content_b64?: string;
    /** MIME type of content, e.g. "audio/mpeg" or "text/plain". */
    content_type?: string;
    /** For streaming: zero-based chunk index within the current episode. */
    chunk_index?: number;
    /** Total number of chunks in the episode if known upfront. */
    total_chunks?: number;
    /** Duration of this audio chunk in milliseconds. */
    duration_ms?: number;
    /** Subscription price in USDC micro (1 USDC = 1_000_000). */
    price_per_epoch_micro?: number;
    /** Monotonic epoch / sequence number for ordering. */
    epoch?: number;
}
export type { NegotiationMsgType, FeedbackPayload, NotarizeBidPayload, DeliverPayload, ProposePayload, CounterPayload, AcceptPayload, NodeIdentity, PeerSnapshot, SendResult, NegotiateResult, SkillMeta, ApiEvent, ActivityEvent, NetworkStats, HostingNode, ActivityParams, } from '@zerox1/core';
//# sourceMappingURL=types.d.ts.map