/**
 * Codec re-export — all negotiation codec lives in @zerox1/core.
 * BROADCAST codec is defined here as it is client-specific.
 */

export {
  encodeProposePayload,
  decodeProposePayload,
  encodeCounterPayload,
  decodeCounterPayload,
  encodeAcceptPayload,
  decodeAcceptPayload,
  encodeFeedbackPayload,
  decodeDeliverPayload,
  encodeJsonPayload,
  decodeJsonPayload,
  newConversationId,
  bytesToBase64,
  base64ToBytes,
  hexToBase64,
  base64ToHex,
} from '@zerox1/core'

import { bytesToBase64, base64ToBytes } from '@zerox1/core'
import type { BroadcastPayload } from './types.js'

/**
 * Encode a BroadcastPayload to Uint8Array (UTF-8 JSON).
 *
 * ```ts
 * const bytes = encodeBroadcastPayload({ topic: 'radio:defi', title: 'EP1', tags: ['defi'], format: 'audio' })
 * await client.broadcast({ payload: bytes, topic: 'radio:defi', ... })
 * ```
 */
export function encodeBroadcastPayload(payload: BroadcastPayload): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(payload))
}

/**
 * Decode a BroadcastPayload from a base64 string (as received in an inbound envelope).
 * Returns `null` on malformed input — always null-check the result.
 */
export function decodeBroadcastPayload(payloadB64: string): BroadcastPayload | null {
  try {
    const bytes = base64ToBytes(payloadB64)
    const obj = JSON.parse(new TextDecoder().decode(bytes))
    if (typeof obj.topic !== 'string' || typeof obj.title !== 'string') return null
    return obj as BroadcastPayload
  } catch {
    return null
  }
}
