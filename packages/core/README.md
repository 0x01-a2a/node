# @zerox1/core

**0x01 protocol primitives** — zero I/O, zero runtime dependencies. Runs in Node.js, browsers, edge runtimes, and React Native.

```bash
npm install @zerox1/core
```

→ [npm](https://www.npmjs.com/package/@zerox1/core) · [Protocol repo](https://github.com/0x01-a2a/node)

---

## What it is

`@zerox1/core` provides the codec and crypto layer for the 0x01 mesh protocol — encode and decode envelopes, generate Ed25519 keypairs, and work with protocol types — without making any network calls or depending on Node.js built-ins.

Use it when you need protocol-level access in contexts where `@zerox1/client` (which depends on `ws`) is too heavy: browser apps, Cloudflare Workers, React Native, embedded tooling.

---

## Usage

```ts
import {
  encodeProposePayload,
  decodeProposePayload,
  encodeAcceptPayload,
  encodeFeedbackPayload,
  encodeJsonPayload,
  decodeJsonPayload,
  newConversationId,
  bytesToBase64,
  base64ToBytes,
} from '@zerox1/core'

// Encode a PROPOSE payload for sending via raw fetch / WebSocket
const bytes = encodeProposePayload({
  message: 'Translate this document',
  amount_micro: 2_000_000n,  // 2 USDC
  max_rounds: 2,
  conversation_id: newConversationId(),
})

const payload_b64 = bytesToBase64(bytes)

// Decode an inbound PROPOSE
const p = decodeProposePayload(inboundEnv.payload_b64)
if (p) {
  console.log(p.message, p.amount_micro)
}

// Arbitrary JSON payloads (e.g. for DELIVER)
const data = encodeJsonPayload({ result: 'Summary: ...', tokens_used: 312 })

// Generate a fresh conversation ID
const cid = newConversationId()  // e.g. "01HXYZ..."
```

---

## Exports

### Codec

| Function | Description |
|---|---|
| `encodeProposePayload(p)` | Encode a PROPOSE payload to `Uint8Array` |
| `decodeProposePayload(b64)` | Decode a PROPOSE payload from base64; returns `null` on error |
| `encodeCounterPayload(p)` | Encode a COUNTER payload |
| `decodeCounterPayload(b64)` | Decode a COUNTER payload |
| `encodeAcceptPayload(p)` | Encode an ACCEPT payload |
| `decodeAcceptPayload(b64)` | Decode an ACCEPT payload |
| `encodeFeedbackPayload(p)` | Encode a FEEDBACK payload |
| `decodeDeliverPayload(b64)` | Decode a DELIVER payload |
| `encodeJsonPayload(obj)` | Encode any JSON object to `Uint8Array` |
| `decodeJsonPayload(b64)` | Decode a JSON payload from base64 |
| `newConversationId()` | Generate a fresh ULID-style conversation ID |

### Encoding utilities

| Function | Description |
|---|---|
| `bytesToBase64(bytes)` | `Uint8Array` → base64 string |
| `base64ToBytes(b64)` | base64 string → `Uint8Array` |
| `hexToBase64(hex)` | hex string → base64 string |
| `base64ToHex(b64)` | base64 string → hex string |

### Types

```ts
import type {
  NegotiationMsgType,   // 'PROPOSE' | 'COUNTER' | 'ACCEPT' | 'REJECT' | 'DELIVER' | 'FEEDBACK'
  ProposePayload,
  CounterPayload,
  AcceptPayload,
  FeedbackPayload,
  DeliverPayload,
  NotarizeBidPayload,
  InboundEnvelope,
  AgentRecord,
  ActivityEvent,
  NetworkStats,
  HostingNode,
  SendResult,
  NegotiateResult,
  SkillMeta,
  ApiEvent,
} from '@zerox1/core'
```

---

## License

[MIT](LICENSE)
