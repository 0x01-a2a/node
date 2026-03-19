"use strict";
/**
 * Protocol codec — identical wire format used by all mesh variants.
 *
 * Negotiation payload wire format:
 *   [16 bytes: LE signed 128-bit integer (amount_micro)] [N bytes: UTF-8 JSON body]
 *
 * Collaboration payloads (enterprise) use plain JSON — no binary prefix.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.encodeProposePayload = encodeProposePayload;
exports.decodeProposePayload = decodeProposePayload;
exports.encodeCounterPayload = encodeCounterPayload;
exports.decodeCounterPayload = decodeCounterPayload;
exports.encodeAcceptPayload = encodeAcceptPayload;
exports.decodeAcceptPayload = decodeAcceptPayload;
exports.encodeFeedbackPayload = encodeFeedbackPayload;
exports.decodeDeliverPayload = decodeDeliverPayload;
exports.encodeJsonPayload = encodeJsonPayload;
exports.decodeJsonPayload = decodeJsonPayload;
exports.newConversationId = newConversationId;
exports.bytesToBase64 = bytesToBase64;
exports.base64ToBytes = base64ToBytes;
exports.hexToBase64 = hexToBase64;
exports.base64ToHex = base64ToHex;
// ── Internal binary helpers ────────────────────────────────────────────────
function writeLEi128(buf, offset, value) {
    let v = value < 0n ? (1n << 128n) + value : value;
    for (let i = 0; i < 16; i++) {
        buf[offset + i] = Number(v & 0xffn);
        v >>= 8n;
    }
}
function readLEi128(buf, offset) {
    let value = 0n;
    for (let i = 15; i >= 0; i--) {
        value = (value << 8n) | BigInt(buf[offset + i]);
    }
    if (value >= (1n << 127n))
        value -= 1n << 128n;
    return value;
}
// ── Negotiation codec ──────────────────────────────────────────────────────
function encodeProposePayload(message, amountMicro = 0n, maxRounds = 2) {
    const jsonBytes = Buffer.from(JSON.stringify({ max_rounds: maxRounds, message }), 'utf8');
    const buf = new Uint8Array(16 + jsonBytes.length);
    writeLEi128(buf, 0, amountMicro);
    buf.set(jsonBytes, 16);
    return buf;
}
function decodeProposePayload(payloadB64) {
    try {
        const bytes = Buffer.from(payloadB64, 'base64');
        if (bytes.length < 16)
            return null;
        const amount_micro = readLEi128(bytes, 0);
        const json = JSON.parse(bytes.slice(16).toString('utf8'));
        return { message: json.message ?? '', amount_micro, max_rounds: json.max_rounds ?? 2 };
    }
    catch {
        return null;
    }
}
function encodeCounterPayload(amountMicro, round, maxRounds, message) {
    const body = { round, max_rounds: maxRounds };
    if (message)
        body.message = message;
    const jsonBytes = Buffer.from(JSON.stringify(body), 'utf8');
    const buf = new Uint8Array(16 + jsonBytes.length);
    writeLEi128(buf, 0, amountMicro);
    buf.set(jsonBytes, 16);
    return buf;
}
function decodeCounterPayload(payloadB64) {
    try {
        const bytes = Buffer.from(payloadB64, 'base64');
        if (bytes.length < 16)
            return null;
        const amount_micro = readLEi128(bytes, 0);
        const json = JSON.parse(bytes.slice(16).toString('utf8'));
        return { amount_micro, round: json.round ?? 1, max_rounds: json.max_rounds ?? 2, message: json.message };
    }
    catch {
        return null;
    }
}
function encodeAcceptPayload(amountMicro, message) {
    const body = {};
    if (message)
        body.message = message;
    const jsonBytes = Buffer.from(JSON.stringify(body), 'utf8');
    const buf = new Uint8Array(16 + jsonBytes.length);
    writeLEi128(buf, 0, amountMicro);
    buf.set(jsonBytes, 16);
    return buf;
}
function decodeAcceptPayload(payloadB64) {
    try {
        const bytes = Buffer.from(payloadB64, 'base64');
        if (bytes.length < 16)
            return null;
        const amount_micro = readLEi128(bytes, 0);
        const json = JSON.parse(bytes.slice(16).toString('utf8'));
        return { amount_micro, message: json.message };
    }
    catch {
        return null;
    }
}
function encodeFeedbackPayload(score, outcome, message) {
    const body = { score, outcome };
    if (message)
        body.message = message;
    return Buffer.from(JSON.stringify(body), 'utf8');
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
function decodeDeliverPayload(payloadB64) {
    try {
        return JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
    }
    catch {
        return null;
    }
}
// ── JSON payload helpers ───────────────────────────────────────────────────
function encodeJsonPayload(obj) {
    return Buffer.from(JSON.stringify(obj), 'utf8');
}
function decodeJsonPayload(payloadB64) {
    try {
        return JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
    }
    catch {
        return null;
    }
}
// ── Utilities ──────────────────────────────────────────────────────────────
function newConversationId() {
    const { randomBytes } = require('crypto');
    return randomBytes(16).toString('hex');
}
function bytesToBase64(bytes) {
    return Buffer.from(bytes).toString('base64');
}
function base64ToBytes(b64) {
    return Buffer.from(b64, 'base64');
}
function hexToBase64(hex) {
    return Buffer.from(hex, 'hex').toString('base64');
}
function base64ToHex(b64) {
    return Buffer.from(b64, 'base64').toString('hex');
}
//# sourceMappingURL=codec.js.map