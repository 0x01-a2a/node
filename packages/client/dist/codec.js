"use strict";
/**
 * Codec re-export — all negotiation codec lives in @zerox1/core.
 * BROADCAST codec is defined here as it is client-specific.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.base64ToHex = exports.hexToBase64 = exports.base64ToBytes = exports.bytesToBase64 = exports.newConversationId = exports.decodeJsonPayload = exports.encodeJsonPayload = exports.decodeDeliverPayload = exports.encodeFeedbackPayload = exports.decodeAcceptPayload = exports.encodeAcceptPayload = exports.decodeCounterPayload = exports.encodeCounterPayload = exports.decodeProposePayload = exports.encodeProposePayload = void 0;
exports.encodeBroadcastPayload = encodeBroadcastPayload;
exports.decodeBroadcastPayload = decodeBroadcastPayload;
var core_1 = require("@zerox1/core");
Object.defineProperty(exports, "encodeProposePayload", { enumerable: true, get: function () { return core_1.encodeProposePayload; } });
Object.defineProperty(exports, "decodeProposePayload", { enumerable: true, get: function () { return core_1.decodeProposePayload; } });
Object.defineProperty(exports, "encodeCounterPayload", { enumerable: true, get: function () { return core_1.encodeCounterPayload; } });
Object.defineProperty(exports, "decodeCounterPayload", { enumerable: true, get: function () { return core_1.decodeCounterPayload; } });
Object.defineProperty(exports, "encodeAcceptPayload", { enumerable: true, get: function () { return core_1.encodeAcceptPayload; } });
Object.defineProperty(exports, "decodeAcceptPayload", { enumerable: true, get: function () { return core_1.decodeAcceptPayload; } });
Object.defineProperty(exports, "encodeFeedbackPayload", { enumerable: true, get: function () { return core_1.encodeFeedbackPayload; } });
Object.defineProperty(exports, "decodeDeliverPayload", { enumerable: true, get: function () { return core_1.decodeDeliverPayload; } });
Object.defineProperty(exports, "encodeJsonPayload", { enumerable: true, get: function () { return core_1.encodeJsonPayload; } });
Object.defineProperty(exports, "decodeJsonPayload", { enumerable: true, get: function () { return core_1.decodeJsonPayload; } });
Object.defineProperty(exports, "newConversationId", { enumerable: true, get: function () { return core_1.newConversationId; } });
Object.defineProperty(exports, "bytesToBase64", { enumerable: true, get: function () { return core_1.bytesToBase64; } });
Object.defineProperty(exports, "base64ToBytes", { enumerable: true, get: function () { return core_1.base64ToBytes; } });
Object.defineProperty(exports, "hexToBase64", { enumerable: true, get: function () { return core_1.hexToBase64; } });
Object.defineProperty(exports, "base64ToHex", { enumerable: true, get: function () { return core_1.base64ToHex; } });
const core_2 = require("@zerox1/core");
/**
 * Encode a BroadcastPayload to Uint8Array (UTF-8 JSON).
 *
 * ```ts
 * const bytes = encodeBroadcastPayload({ topic: 'radio:defi', title: 'EP1', tags: ['defi'], format: 'audio' })
 * await client.broadcast({ payload: bytes, topic: 'radio:defi', ... })
 * ```
 */
function encodeBroadcastPayload(payload) {
    return new TextEncoder().encode(JSON.stringify(payload));
}
/**
 * Decode a BroadcastPayload from a base64 string (as received in an inbound envelope).
 * Returns `null` on malformed input — always null-check the result.
 */
function decodeBroadcastPayload(payloadB64) {
    try {
        const bytes = (0, core_2.base64ToBytes)(payloadB64);
        const obj = JSON.parse(new TextDecoder().decode(bytes));
        if (typeof obj.topic !== 'string' || typeof obj.title !== 'string')
            return null;
        return obj;
    }
    catch {
        return null;
    }
}
//# sourceMappingURL=codec.js.map