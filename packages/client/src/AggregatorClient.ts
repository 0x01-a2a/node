/**
 * AggregatorClient — HTTP + WebSocket client for the 0x01 aggregator REST API.
 *
 * The aggregator is a separate service from the node. It tracks reputation,
 * agent discovery, and activity across the mesh. This client is read-mostly.
 *
 * Public aggregator: https://agg.0x01.world
 */

import WebSocket from 'ws'
import type {
  AgentRecord,
  AgentProfile,
  ActivityEvent,
  NetworkStats,
  HostingNode,
  AgentsParams,
  ActivityParams,
} from './types.js'

export interface AggregatorClientOptions {
  /** Aggregator base URL, e.g. "https://agg.0x01.world" */
  url: string
  /** API key for gated read endpoints (reputation, leaderboard, etc.) */
  apiKey?: string
}

export class AggregatorClient {
  private readonly baseUrl: string
  private readonly apiKey: string | undefined

  constructor(opts: AggregatorClientOptions) {
    this.baseUrl = opts.url.replace(/\/$/, '')
    this.apiKey = opts.apiKey
  }

  // ── HTTP helpers ──────────────────────────────────────────────────────────

  private headers(): Record<string, string> {
    const h: Record<string, string> = {}
    if (this.apiKey) h['Authorization'] = `Bearer ${this.apiKey}`
    return h
  }

  private async get<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
    let url = `${this.baseUrl}${path}`
    if (params) {
      const qs = Object.entries(params)
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
        .join('&')
      if (qs) url += `?${qs}`
    }
    const res = await fetch(url, { headers: this.headers() })
    if (!res.ok) throw new Error(`GET ${path} → ${res.status}: ${await res.text()}`)
    return res.json() as Promise<T>
  }

  // ── Agent discovery ───────────────────────────────────────────────────────

  /** List agents on the mesh, optionally filtered by country or capabilities. */
  async agents(params?: AgentsParams): Promise<AgentRecord[]> {
    return this.get('/agents', {
      limit: params?.limit,
      country: params?.country,
      capabilities: params?.capabilities,
    })
  }

  /** Get full profile for a single agent (reputation, capabilities, recent disputes). */
  async agentProfile(agentId: string): Promise<AgentProfile> {
    return this.get(`/agents/${agentId}/profile`)
  }

  /** Reverse-lookup: get all agents registered to a wallet address. */
  async agentsByOwner(wallet: string): Promise<AgentRecord[]> {
    return this.get(`/agents/by-owner/${wallet}`)
  }

  /** Get the owner record for an agent (unclaimed / pending / claimed). */
  async agentOwner(agentId: string): Promise<unknown> {
    return this.get(`/agents/${agentId}/owner`)
  }

  // ── Reputation (API-key gated) ────────────────────────────────────────────

  /** Detailed reputation snapshot. Requires API key. */
  async reputation(agentId: string): Promise<unknown> {
    return this.get(`/reputation/${agentId}`)
  }

  // ── Activity feed ─────────────────────────────────────────────────────────

  /**
   * Fetch recent activity events (JOIN, FEEDBACK, DISPUTE, VERDICT).
   * Use `params.before` for cursor pagination (pass last seen `id`).
   */
  async activity(params?: ActivityParams): Promise<ActivityEvent[]> {
    return this.get('/activity', {
      limit: params?.limit,
      before: params?.before,
    })
  }

  /**
   * Subscribe to real-time activity events via WebSocket.
   * Returns an unsubscribe function.
   *
   * ```ts
   * const stop = agg.watchActivity((event) => {
   *   console.log(event.event_type, event.agent_id)
   * })
   * // later:
   * stop()
   * ```
   */
  watchActivity(handler: (event: ActivityEvent) => void): () => void {
    const wsUrl = this.baseUrl.replace(/^http/, 'ws') + '/ws/activity'
    let ws: WebSocket | null = null
    let closed = false
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null

    const connect = () => {
      if (closed) return
      ws = new WebSocket(wsUrl)
      ws.on('message', (data) => {
        try { handler(JSON.parse(data.toString()) as ActivityEvent) } catch { /* ignore */ }
      })
      ws.on('close', () => {
        if (!closed) reconnectTimer = setTimeout(connect, 3000)
      })
      ws.on('error', () => { /* handled by close */ })
    }

    connect()
    return () => {
      closed = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      ws?.close()
    }
  }

  // ── Network stats ─────────────────────────────────────────────────────────

  /** High-level stats: total agents, total interactions, uptime. */
  async networkStats(): Promise<NetworkStats> {
    return this.get('/stats/network')
  }

  // ── Hosting nodes ─────────────────────────────────────────────────────────

  /** List currently active hosting nodes (seen in last 120s). */
  async hostingNodes(): Promise<HostingNode[]> {
    return this.get('/hosting/nodes')
  }

  // ── Blobs ─────────────────────────────────────────────────────────────────

  /** Download a blob by CID. Returns raw Response for streaming. */
  async downloadBlob(cid: string): Promise<Response> {
    const res = await fetch(`${this.baseUrl}/blobs/${cid}`, { headers: this.headers() })
    if (!res.ok) throw new Error(`GET /blobs/${cid} → ${res.status}`)
    return res
  }
}
