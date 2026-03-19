/**
 * Protocol codec — identical wire format used by all mesh variants.
 *
 * Negotiation payload wire format:
 *   [16 bytes: LE signed 128-bit integer (amount_micro)] [N bytes: UTF-8 JSON body]
 *
 * Collaboration payloads (enterprise) use plain JSON — no binary prefix.
 */
import type { ProposePayload, CounterPayload, AcceptPayload, DeliverPayload } from './types.js';
export declare function encodeProposePayload(message: string, amountMicro?: bigint, maxRounds?: number): Uint8Array;
export declare function decodeProposePayload(payloadB64: string): ProposePayload | null;
export declare function encodeCounterPayload(amountMicro: bigint, round: number, maxRounds: number, message?: string): Uint8Array;
export declare function decodeCounterPayload(payloadB64: string): CounterPayload | null;
export declare function encodeAcceptPayload(amountMicro: bigint, message?: string): Uint8Array;
export declare function decodeAcceptPayload(payloadB64: string): AcceptPayload | null;
export declare function encodeFeedbackPayload(score: number, outcome: 'positive' | 'neutral' | 'negative', message?: string): Uint8Array;
/**
 * Decode a DELIVER payload from an inbound envelope's payload_b64.
 *
 * ```ts
 * agent.on('DELIVER', (env) => {
 *   const d = decodeDeliverPayload(env.payload_b64)
 *   if (!d) return
 *   console.log(`Delivered: ${d.summary}, fee: $${d.fee_usdc ?? 0}`)
 *   // Note: fee_usdc is in the payload — NOT on env.fee_usdc (that field doesn't exist)
 * })
 * ```
 */
export declare function decodeDeliverPayload(payloadB64: string): DeliverPayload | null;
export declare function encodeJsonPayload(obj: unknown): Uint8Array;
export declare function decodeJsonPayload<T = unknown>(payloadB64: string): T | null;
export declare function newConversationId(): string;
export declare function bytesToBase64(bytes: Uint8Array): string;
export declare function base64ToBytes(b64: string): Uint8Array;
export declare function hexToBase64(hex: string): string;
export declare function base64ToHex(b64: string): string;
//# sourceMappingURL=codec.d.ts.map