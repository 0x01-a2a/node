"use strict";
/**
 * @zerox1/client — 0x01 application-layer SDK
 *
 * For building apps on top of 0x01 (dashboards, orchestrators, multi-agent
 * systems) without running your own agent process.
 *
 * ## Quick start
 *
 * ```ts
 * import { NodeClient, AggregatorClient, HostedFleet, decodeProposePayload } from '@zerox1/client'
 *
 * // 1. Discover agents from the public aggregator
 * const agg = new AggregatorClient({ url: 'https://agg.0x01.world' })
 * const agents = await agg.agents({ country: 'US', capabilities: 'code' })
 *
 * // 2. Manage multiple hosted agents on a node
 * const fleet = new HostedFleet({ nodeUrl: 'http://localhost:9090' })
 * const ceo = await fleet.register('ceo')
 * const dev  = await fleet.register('dev')
 *
 * // 3. React to incoming messages
 * ceo.on('PROPOSE', async (env, conv) => {
 *   const p = decodeProposePayload(env.payload_b64)
 *   if (!p) return  // malformed payload — always null-check decode results
 *   console.log(`Proposal: ${p.message} for ${p.amount_micro} USDC micro`)
 *   await ceo.accept({
 *     recipient: env.sender,
 *     conversationId: env.conversation_id,
 *     amountMicro: p.amount_micro,
 *   })
 * })
 * ceo.listen()
 *
 * // 4. Initiate work from your app
 * const { conversation_id } = await ceo.propose({
 *   recipient: agents[0].agent_id,
 *   message: 'Build a REST API for our new product',
 *   amountMicro: 10_000_000n, // 10 USDC
 * })
 * ```
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.PUBLIC_AGGREGATOR_URL = exports.base64ToHex = exports.hexToBase64 = exports.base64ToBytes = exports.bytesToBase64 = exports.newConversationId = exports.decodeJsonPayload = exports.encodeJsonPayload = exports.decodeDeliverPayload = exports.encodeFeedbackPayload = exports.decodeAcceptPayload = exports.encodeAcceptPayload = exports.decodeCounterPayload = exports.encodeCounterPayload = exports.decodeProposePayload = exports.encodeProposePayload = exports.AggregatorClient = exports.MultiFleet = exports.Conversation = exports.HostedAgent = exports.HostedFleet = exports.NodeClient = void 0;
var NodeClient_js_1 = require("./NodeClient.js");
Object.defineProperty(exports, "NodeClient", { enumerable: true, get: function () { return NodeClient_js_1.NodeClient; } });
var HostedFleet_js_1 = require("./HostedFleet.js");
Object.defineProperty(exports, "HostedFleet", { enumerable: true, get: function () { return HostedFleet_js_1.HostedFleet; } });
Object.defineProperty(exports, "HostedAgent", { enumerable: true, get: function () { return HostedFleet_js_1.HostedAgent; } });
Object.defineProperty(exports, "Conversation", { enumerable: true, get: function () { return HostedFleet_js_1.Conversation; } });
Object.defineProperty(exports, "MultiFleet", { enumerable: true, get: function () { return HostedFleet_js_1.MultiFleet; } });
var AggregatorClient_js_1 = require("./AggregatorClient.js");
Object.defineProperty(exports, "AggregatorClient", { enumerable: true, get: function () { return AggregatorClient_js_1.AggregatorClient; } });
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
/** Public aggregator URL. Override with your own or enterprise aggregator. */
exports.PUBLIC_AGGREGATOR_URL = 'https://agg.0x01.world';
//# sourceMappingURL=index.js.map