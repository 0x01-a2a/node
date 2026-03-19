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

export type {
  NegotiationMsgType,
  InboundEnvelope,
  FeedbackPayload,
  NotarizeBidPayload,
  ProposePayload,
  CounterPayload,
  AcceptPayload,
  DeliverPayload,
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
} from './types.js'

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
} from './codec.js'

export type { Keypair } from './crypto.js'
export {
  generateKeypair,
  keypairFromSeed,
  sign,
  verify,
  publicKeyToAgentId,
  agentIdToPublicKey,
} from './crypto.js'
