/**
 * Core negotiation message types shared across all mesh variants.
 * Platform packages extend this into their own `MsgType` union.
 *
 * Public mesh adds: VERDICT, ADVERTISE, DISCOVER, BEACON, NOTARIZE_BID, NOTARIZE_ASSIGN
 * Enterprise adds: DEAL_CANCEL + collaboration types (ASSIGN, REPORT, etc.)
 */
export type NegotiationMsgType = 'PROPOSE' | 'COUNTER' | 'ACCEPT' | 'REJECT' | 'DELIVER' | 'DISPUTE' | 'FEEDBACK';
export interface FeedbackPayload {
    score: number;
    outcome: 'positive' | 'neutral' | 'negative';
    message?: string;
}
export interface NotarizeBidPayload {
    task_id: string;
    amount_micro: number;
    deadline_secs: number;
}
/**
 * Generic inbound envelope. T is the msg_type union for this mesh variant.
 * Use the concrete InboundEnvelope exported by @zerox1/client or
 * @zerox1/enterprise-client rather than this generic form directly.
 *
 * The node pre-decodes `feedback` for FEEDBACK messages so handlers don't
 * need to call decodeJsonPayload — the fields are already available.
 */
export interface InboundEnvelope<T extends string = string> {
    msg_type: T;
    sender: string;
    recipient: string;
    conversation_id: string;
    nonce: number;
    payload_b64: string;
    /** Pre-decoded by the node — only present on FEEDBACK messages. */
    feedback?: FeedbackPayload;
}
export interface ProposePayload {
    message: string;
    amount_micro: bigint;
    max_rounds: number;
}
export interface CounterPayload {
    message?: string;
    amount_micro: bigint;
    round: number;
    max_rounds: number;
}
export interface AcceptPayload {
    message?: string;
    amount_micro: bigint;
}
/**
 * DELIVER payload — sent by an agent to submit completed work.
 * The `fee_usdc` field is the amount the agent charges for this delivery.
 * This is application-level JSON encoded in payload_b64 — use
 * `decodeDeliverPayload()` to parse it from an inbound DELIVER envelope.
 *
 * Note: `fee_usdc` is in the payload, NOT on the envelope itself.
 */
export interface DeliverPayload {
    /** Human-readable summary of the work delivered. */
    summary?: string;
    /** USDC amount charged for this delivery (e.g. 1.5 = $1.50). */
    fee_usdc?: number;
    /** Result data — structure is agent/app defined. */
    result?: unknown;
}
export interface NodeIdentity {
    agent_id: string;
    name: string;
}
export interface PeerSnapshot {
    agent_id: string;
    peer_id?: string;
    last_active_epoch?: number;
}
export interface ReputationSnapshot {
    agent_id: string;
    reliability: number;
    cooperation: number;
    total_tasks: number;
    total_disputes: number;
    last_active_epoch?: number;
}
export interface SendResult {
    nonce: number;
    payload_hash: string;
}
export interface NegotiateResult {
    conversation_id: string;
    nonce: number;
    payload_hash: string;
}
export interface SkillMeta {
    name: string;
    version: string;
    url: string;
}
export interface ApiEvent {
    event_type: string;
    agent_id?: string;
    data?: unknown;
}
export interface AgentRecord {
    agent_id: string;
    name?: string;
    capabilities?: string[];
    reputation?: number;
    stake?: number;
}
export interface AgentProfile extends AgentRecord {
    total_tasks?: number;
    total_disputes?: number;
    last_active?: number;
}
export interface ActivityEvent {
    id: number;
    event_type: string;
    agent_id: string;
    counterpart_id?: string;
    score?: number;
    conversation_id?: string;
    created_at: number;
}
export interface NetworkStats {
    agent_count: number;
    interaction_count: number;
    started_at: number;
}
export interface HostingNode {
    node_id: string;
    name?: string;
    fee_bps?: number;
    api_url: string;
    hosted_count: number;
    first_seen?: number;
    last_seen: number;
}
export interface AgentsParams {
    limit?: number;
}
export interface ActivityParams {
    limit?: number;
    before?: number;
}
//# sourceMappingURL=types.d.ts.map