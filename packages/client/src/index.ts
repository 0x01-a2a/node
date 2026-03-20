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

export { NodeClient } from './NodeClient.js'
export type { NodeClientOptions, SendParams, ProposeParams, CounterParams, AcceptParams, BroadcastParams } from './NodeClient.js'

export { HostedFleet, HostedAgent, Conversation, MultiFleet } from './HostedFleet.js'
export type { HostedFleetOptions, HostedAgentOptions, HostedSendParams, TokenStore, MultiFleetOptions } from './HostedFleet.js'

export { AggregatorClient } from './AggregatorClient.js'
export type { AggregatorClientOptions } from './AggregatorClient.js'

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
  encodeBroadcastPayload,
  decodeBroadcastPayload,
} from './codec.js'

export type {
  NegotiationMsgType,
  MsgType,
  InboundEnvelope,
  FeedbackPayload,
  NotarizeBidPayload,
  DeliverPayload,
  ProposePayload,
  CounterPayload,
  AcceptPayload,
  NodeIdentity,
  PeerSnapshot,
  ReputationSnapshot,
  SendResult,
  NegotiateResult,
  SkillMeta,
  ApiEvent,
  AgentRecord,
  AgentProfile,
  ActivityEvent,
  NetworkStats,
  HostingNode,
  AgentsParams,
  ActivityParams,
  BroadcastPayload,
} from './types.js'

/** Public aggregator URL. Override with your own or enterprise aggregator. */
export const PUBLIC_AGGREGATOR_URL = 'https://agg.0x01.world'
