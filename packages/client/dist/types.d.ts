/**
 * Public mesh type extensions — re-exports @zerox1/core base types and adds
 * public-mesh specific fields (geo, latency, system message types).
 */
import type { NegotiationMsgType, InboundEnvelope as CoreInboundEnvelope, AgentRecord as CoreAgentRecord, AgentsParams as CoreAgentsParams, NotarizeBidPayload } from '@zerox1/core';
/** Full public mesh message type — negotiation + system messages. */
export type MsgType = NegotiationMsgType | 'VERDICT' | 'ADVERTISE' | 'DISCOVER' | 'BEACON' | 'NOTARIZE_BID' | 'NOTARIZE_ASSIGN';
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
export type { NegotiationMsgType, FeedbackPayload, NotarizeBidPayload, DeliverPayload, ProposePayload, CounterPayload, AcceptPayload, NodeIdentity, PeerSnapshot, SendResult, NegotiateResult, SkillMeta, ApiEvent, ActivityEvent, NetworkStats, HostingNode, ActivityParams, } from '@zerox1/core';
//# sourceMappingURL=types.d.ts.map