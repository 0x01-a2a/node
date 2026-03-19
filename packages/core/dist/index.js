"use strict";
/**
 * @zerox1/core — 0x01 protocol primitives
 *
 * Platform-agnostic, zero I/O. Works in Node.js, browsers, React Native,
 * WASM runtimes, and anything that can run JavaScript.
 *
 * Contains:
 * - All shared message types and payload interfaces
 * - Negotiation payload encode/decode (PROPOSE / COUNTER / ACCEPT)
 * - JSON payload helpers for collaboration messages
 * - Ed25519 keypair generation and signing
 * - Wire format utilities (base64, hex conversions)
 *
 * Platform-specific packages (@zerox1/client, @zerox1/enterprise-client,
 * @zerox1/react-native) depend on this package and extend its types for
 * their respective mesh variant.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.agentIdToPublicKey = exports.publicKeyToAgentId = exports.verify = exports.sign = exports.keypairFromSeed = exports.generateKeypair = exports.base64ToHex = exports.hexToBase64 = exports.base64ToBytes = exports.bytesToBase64 = exports.newConversationId = exports.decodeJsonPayload = exports.encodeJsonPayload = exports.decodeDeliverPayload = exports.encodeFeedbackPayload = exports.decodeAcceptPayload = exports.encodeAcceptPayload = exports.decodeCounterPayload = exports.encodeCounterPayload = exports.decodeProposePayload = exports.encodeProposePayload = void 0;
var codec_js_1 = require("./codec.js");
Object.defineProperty(exports, "encodeProposePayload", { enumerable: true, get: function () { return codec_js_1.encodeProposePayload; } });
Object.defineProperty(exports, "decodeProposePayload", { enumerable: true, get: function () { return codec_js_1.decodeProposePayload; } });
Object.defineProperty(exports, "encodeCounterPayload", { enumerable: true, get: function () { return codec_js_1.encodeCounterPayload; } });
Object.defineProperty(exports, "decodeCounterPayload", { enumerable: true, get: function () { return codec_js_1.decodeCounterPayload; } });
Object.defineProperty(exports, "encodeAcceptPayload", { enumerable: true, get: function () { return codec_js_1.encodeAcceptPayload; } });
Object.defineProperty(exports, "decodeAcceptPayload", { enumerable: true, get: function () { return codec_js_1.decodeAcceptPayload; } });
Object.defineProperty(exports, "encodeFeedbackPayload", { enumerable: true, get: function () { return codec_js_1.encodeFeedbackPayload; } });
Object.defineProperty(exports, "decodeDeliverPayload", { enumerable: true, get: function () { return codec_js_1.decodeDeliverPayload; } });
Object.defineProperty(exports, "encodeJsonPayload", { enumerable: true, get: function () { return codec_js_1.encodeJsonPayload; } });
Object.defineProperty(exports, "decodeJsonPayload", { enumerable: true, get: function () { return codec_js_1.decodeJsonPayload; } });
Object.defineProperty(exports, "newConversationId", { enumerable: true, get: function () { return codec_js_1.newConversationId; } });
Object.defineProperty(exports, "bytesToBase64", { enumerable: true, get: function () { return codec_js_1.bytesToBase64; } });
Object.defineProperty(exports, "base64ToBytes", { enumerable: true, get: function () { return codec_js_1.base64ToBytes; } });
Object.defineProperty(exports, "hexToBase64", { enumerable: true, get: function () { return codec_js_1.hexToBase64; } });
Object.defineProperty(exports, "base64ToHex", { enumerable: true, get: function () { return codec_js_1.base64ToHex; } });
var crypto_js_1 = require("./crypto.js");
Object.defineProperty(exports, "generateKeypair", { enumerable: true, get: function () { return crypto_js_1.generateKeypair; } });
Object.defineProperty(exports, "keypairFromSeed", { enumerable: true, get: function () { return crypto_js_1.keypairFromSeed; } });
Object.defineProperty(exports, "sign", { enumerable: true, get: function () { return crypto_js_1.sign; } });
Object.defineProperty(exports, "verify", { enumerable: true, get: function () { return crypto_js_1.verify; } });
Object.defineProperty(exports, "publicKeyToAgentId", { enumerable: true, get: function () { return crypto_js_1.publicKeyToAgentId; } });
Object.defineProperty(exports, "agentIdToPublicKey", { enumerable: true, get: function () { return crypto_js_1.agentIdToPublicKey; } });
//# sourceMappingURL=index.js.map