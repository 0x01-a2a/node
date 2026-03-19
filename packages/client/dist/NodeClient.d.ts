/**
 * NodeClient — HTTP + WebSocket client for the zerox1-node REST API.
 *
 * Works with both local nodes (127.0.0.1:9090) and remote nodes.
 * Does not manage the node binary — use @zerox1/sdk for that.
 */
import type { NodeIdentity, PeerSnapshot, ReputationSnapshot, SendResult, NegotiateResult, SkillMeta, ApiEvent, InboundEnvelope, MsgType } from './types.js';
export interface NodeClientOptions {
    /** Node API base URL, e.g. "http://127.0.0.1:9090" or "https://my-node.com" */
    url: string;
    /** Master secret (--api-secret / ZX01_API_SECRET). Required for send/negotiate. */
    secret?: string;
}
export interface SendParams {
    msgType: MsgType;
    /** Recipient agent ID (64-char hex). Omit for broadcast messages. */
    recipient?: string;
    conversationId?: string;
    /** Raw payload bytes. Will be base64-encoded automatically. */
    payload: Uint8Array;
}
export interface ProposeParams {
    recipient: string;
    message: string;
    conversationId?: string;
    amountMicro?: bigint;
    maxRounds?: number;
}
export interface CounterParams {
    recipient: string;
    conversationId: string;
    amountMicro: bigint;
    round: number;
    maxRounds?: number;
    message?: string;
}
export interface AcceptParams {
    recipient: string;
    conversationId: string;
    amountMicro: bigint;
    message?: string;
}
export declare class NodeClient {
    private readonly baseUrl;
    private readonly secret;
    constructor(opts: NodeClientOptions);
    private headers;
    private get;
    private post;
    identity(): Promise<NodeIdentity>;
    peers(): Promise<PeerSnapshot[]>;
    reputation(agentId: string): Promise<ReputationSnapshot>;
    send(params: SendParams): Promise<SendResult>;
    propose(params: ProposeParams): Promise<NegotiateResult>;
    counter(params: CounterParams): Promise<NegotiateResult>;
    accept(params: AcceptParams): Promise<NegotiateResult>;
    listSkills(): Promise<SkillMeta[]>;
    installSkill(url: string, name?: string): Promise<void>;
    removeSkill(name: string): Promise<void>;
    /**
     * Subscribe to the local agent inbox.
     * Returns an unsubscribe function.
     */
    inbox(handler: (env: InboundEnvelope) => void): () => void;
    /**
     * Subscribe to node events (peer connect/disconnect, etc.).
     * Returns an unsubscribe function.
     */
    events(handler: (event: ApiEvent) => void): () => void;
    private _wsSubscribe;
}
//# sourceMappingURL=NodeClient.d.ts.map