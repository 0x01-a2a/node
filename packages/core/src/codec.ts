/**
 * Protocol codec — identical wire format used by all mesh variants.
 *
 * Negotiation payload wire format:
 *   [16 bytes: LE signed 128-bit integer (amount_micro)] [N bytes: UTF-8 JSON body]
 *
 * Collaboration payloads (enterprise) use plain JSON — no binary prefix.
 */

import type { ProposePayload, CounterPayload, AcceptPayload, DeliverPayload } from './types.js'

// ── Internal binary helpers ────────────────────────────────────────────────

function writeLEi128(buf: Uint8Array, offset: number, value: bigint): void {
  let v = value < 0n ? (1n << 128n) + value : value
  for (let i = 0; i < 16; i++) {
    buf[offset + i] = Number(v & 0xffn)
    v >>= 8n
  }
}

function readLEi128(buf: Uint8Array, offset: number): bigint {
  let value = 0n
  for (let i = 15; i >= 0; i--) {
    value = (value << 8n) | BigInt(buf[offset + i])
  }
  if (value >= (1n << 127n)) value -= 1n << 128n
  return value
}

// ── Negotiation codec ──────────────────────────────────────────────────────

export function encodeProposePayload(
  message: string,
  amountMicro: bigint = 0n,
  maxRounds: number = 2,
): Uint8Array {
  const jsonBytes = Buffer.from(JSON.stringify({ max_rounds: maxRounds, message }), 'utf8')
  const buf = new Uint8Array(16 + jsonBytes.length)
  writeLEi128(buf, 0, amountMicro)
  buf.set(jsonBytes, 16)
  return buf
}

export function decodeProposePayload(payloadB64: string): ProposePayload | null {
  try {
    const bytes = Buffer.from(payloadB64, 'base64')
    if (bytes.length < 16) return null
    const amount_micro = readLEi128(bytes, 0)
    const json = JSON.parse(bytes.slice(16).toString('utf8'))
    return { message: json.message ?? '', amount_micro, max_rounds: json.max_rounds ?? 2 }
  } catch { return null }
}

export function encodeCounterPayload(
  amountMicro: bigint,
  round: number,
  maxRounds: number,
  message?: string,
): Uint8Array {
  const body: Record<string, unknown> = { round, max_rounds: maxRounds }
  if (message) body.message = message
  const jsonBytes = Buffer.from(JSON.stringify(body), 'utf8')
  const buf = new Uint8Array(16 + jsonBytes.length)
  writeLEi128(buf, 0, amountMicro)
  buf.set(jsonBytes, 16)
  return buf
}

export function decodeCounterPayload(payloadB64: string): CounterPayload | null {
  try {
    const bytes = Buffer.from(payloadB64, 'base64')
    if (bytes.length < 16) return null
    const amount_micro = readLEi128(bytes, 0)
    const json = JSON.parse(bytes.slice(16).toString('utf8'))
    return { amount_micro, round: json.round ?? 1, max_rounds: json.max_rounds ?? 2, message: json.message }
  } catch { return null }
}

export function encodeAcceptPayload(amountMicro: bigint, message?: string): Uint8Array {
  const body: Record<string, unknown> = {}
  if (message) body.message = message
  const jsonBytes = Buffer.from(JSON.stringify(body), 'utf8')
  const buf = new Uint8Array(16 + jsonBytes.length)
  writeLEi128(buf, 0, amountMicro)
  buf.set(jsonBytes, 16)
  return buf
}

export function decodeAcceptPayload(payloadB64: string): AcceptPayload | null {
  try {
    const bytes = Buffer.from(payloadB64, 'base64')
    if (bytes.length < 16) return null
    const amount_micro = readLEi128(bytes, 0)
    const json = JSON.parse(bytes.slice(16).toString('utf8'))
    return { amount_micro, message: json.message }
  } catch { return null }
}

export function encodeFeedbackPayload(
  score: number,
  outcome: 'positive' | 'neutral' | 'negative',
  message?: string,
): Uint8Array {
  const body: Record<string, unknown> = { score, outcome }
  if (message) body.message = message
  return Buffer.from(JSON.stringify(body), 'utf8')
}

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
export function decodeDeliverPayload(payloadB64: string): DeliverPayload | null {
  try { return JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8')) as DeliverPayload }
  catch { return null }
}

// ── JSON payload helpers ───────────────────────────────────────────────────

export function encodeJsonPayload(obj: unknown): Uint8Array {
  return Buffer.from(JSON.stringify(obj), 'utf8')
}

export function decodeJsonPayload<T = unknown>(payloadB64: string): T | null {
  try { return JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8')) as T }
  catch { return null }
}

// ── Utilities ──────────────────────────────────────────────────────────────

export function newConversationId(): string {
  const { randomBytes } = require('crypto') as typeof import('crypto')
  return randomBytes(16).toString('hex')
}

export function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64')
}

export function base64ToBytes(b64: string): Uint8Array {
  return Buffer.from(b64, 'base64')
}

export function hexToBase64(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64')
}

export function base64ToHex(b64: string): string {
  return Buffer.from(b64, 'base64').toString('hex')
}
