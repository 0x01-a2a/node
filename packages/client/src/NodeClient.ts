/**
 * NodeClient — HTTP + WebSocket client for the zerox1-node REST API.
 *
 * Works with both local nodes (127.0.0.1:9090) and remote nodes.
 * Does not manage the node binary — use @zerox1/sdk for that.
 */

import WebSocket from 'ws'
import type {
  NodeIdentity,
  PeerSnapshot,
  ReputationSnapshot,
  SendResult,
  NegotiateResult,
  SkillMeta,
  ApiEvent,
  InboundEnvelope,
  MsgType,
} from './types.js'
import { bytesToBase64, newConversationId } from './codec.js'

export interface NodeClientOptions {
  /** Node API base URL, e.g. "http://127.0.0.1:9090" or "https://my-node.com" */
  url: string
  /** Master secret (--api-secret / ZX01_API_SECRET). Required for send/negotiate. */
  secret?: string
}

export interface SendParams {
  msgType: MsgType
  /** Recipient agent ID (64-char hex). Omit for broadcast messages. */
  recipient?: string
  conversationId?: string
  /** Raw payload bytes. Will be base64-encoded automatically. */
  payload: Uint8Array
}

export interface ProposeParams {
  recipient: string
  message: string
  conversationId?: string
  amountMicro?: bigint
  maxRounds?: number
}

export interface CounterParams {
  recipient: string
  conversationId: string
  amountMicro: bigint
  round: number
  maxRounds?: number
  message?: string
}

export interface AcceptParams {
  recipient: string
  conversationId: string
  amountMicro: bigint
  message?: string
}

export class NodeClient {
  private readonly baseUrl: string
  private readonly secret: string | undefined

  constructor(opts: NodeClientOptions) {
    this.baseUrl = opts.url.replace(/\/$/, '')
    this.secret = opts.secret
  }

  // ── HTTP helpers ──────────────────────────────────────────────────────────

  private headers(extra?: Record<string, string>): Record<string, string> {
    const h: Record<string, string> = { 'Content-Type': 'application/json' }
    if (this.secret) h['Authorization'] = `Bearer ${this.secret}`
    return { ...h, ...extra }
  }

  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, { headers: this.headers() })
    if (!res.ok) throw new Error(`GET ${path} → ${res.status}: ${await res.text()}`)
    return res.json() as Promise<T>
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(body),
    })
    if (!res.ok) throw new Error(`POST ${path} → ${res.status}: ${await res.text()}`)
    return res.json() as Promise<T>
  }

  // ── Identity & status ─────────────────────────────────────────────────────

  async identity(): Promise<NodeIdentity> {
    return this.get('/identity')
  }

  async peers(): Promise<PeerSnapshot[]> {
    return this.get('/peers')
  }

  async reputation(agentId: string): Promise<ReputationSnapshot> {
    return this.get(`/reputation/${agentId}`)
  }

  // ── Send ──────────────────────────────────────────────────────────────────

  async send(params: SendParams): Promise<SendResult> {
    return this.post('/envelopes/send', {
      msg_type: params.msgType,
      recipient: params.recipient ?? null,
      conversation_id: params.conversationId ?? newConversationId(),
      payload_b64: bytesToBase64(params.payload),
    })
  }

  // ── Negotiate shortcuts ───────────────────────────────────────────────────

  async propose(params: ProposeParams): Promise<NegotiateResult> {
    return this.post('/negotiate/propose', {
      recipient: params.recipient,
      conversation_id: params.conversationId ?? null,
      amount_usdc_micro: params.amountMicro !== undefined ? Number(params.amountMicro) : 0,
      max_rounds: params.maxRounds ?? 2,
      message: params.message,
    })
  }

  async counter(params: CounterParams): Promise<NegotiateResult> {
    return this.post('/negotiate/counter', {
      recipient: params.recipient,
      conversation_id: params.conversationId,
      amount_usdc_micro: Number(params.amountMicro),
      round: params.round,
      max_rounds: params.maxRounds ?? null,
      message: params.message ?? null,
    })
  }

  async accept(params: AcceptParams): Promise<NegotiateResult> {
    return this.post('/negotiate/accept', {
      recipient: params.recipient,
      conversation_id: params.conversationId,
      amount_usdc_micro: Number(params.amountMicro),
      message: params.message ?? null,
    })
  }

  // ── Skills ────────────────────────────────────────────────────────────────

  async listSkills(): Promise<SkillMeta[]> {
    return this.get('/skill/list')
  }

  async installSkill(url: string, name?: string): Promise<void> {
    await this.post('/skill/install-url', { url, name: name ?? null })
  }

  async removeSkill(name: string): Promise<void> {
    await this.post('/skill/remove', { name })
  }

  // ── WebSocket subscriptions ───────────────────────────────────────────────

  /**
   * Subscribe to the local agent inbox.
   * Returns an unsubscribe function.
   */
  inbox(handler: (env: InboundEnvelope) => void): () => void {
    return this._wsSubscribe('/ws/inbox', handler)
  }

  /**
   * Subscribe to node events (peer connect/disconnect, etc.).
   * Returns an unsubscribe function.
   */
  events(handler: (event: ApiEvent) => void): () => void {
    return this._wsSubscribe('/ws/events', handler)
  }

  private _wsSubscribe<T>(path: string, handler: (msg: T) => void): () => void {
    const wsUrl = this.baseUrl.replace(/^http/, 'ws') + path
    const params = this.secret ? `?token=${this.secret}` : ''
    let ws: WebSocket | null = null
    let closed = false
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null

    const connect = () => {
      if (closed) return
      ws = new WebSocket(`${wsUrl}${params}`)
      ws.on('message', (data) => {
        try { handler(JSON.parse(data.toString()) as T) } catch (e) {
          console.error('[NodeClient] failed to parse message:', e)
        }
      })
      ws.on('close', () => {
        if (!closed) reconnectTimer = setTimeout(connect, 3000)
      })
      ws.on('error', (e) => {
        console.error('[NodeClient] WebSocket error:', e)
      })
    }

    connect()

    return () => {
      closed = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      ws?.close()
    }
  }
}
