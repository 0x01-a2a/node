import { Zerox1Agent, InboundEnvelope, SendParams } from '@zerox1/sdk'
import * as fs from 'fs'
import * as path from 'path'

// ============================================================================
// Types
// ============================================================================

type SessionStep = 'negotiating' | 'verifying'

interface SessionState {
  agentId: string
  conversationId: string
  step: SessionStep
  lastActivity: number
}

// ============================================================================
// Configuration
// ============================================================================

interface GuardianConfig {
  /** Path to Ed25519 keypair file */
  keypairPath: string
  /** Solana RPC URL for on-chain interactions */
  rpcUrl?: string
  /** SATI mint address (optional for devnet) */
  satiMint?: string
  /** Timeout for session inactivity in ms (default: 60s) */
  sessionTimeoutMs?: number
}

// ============================================================================
// GuardianNPC Reference Agent
// ============================================================================

export class GuardianNPC {
  private agent: Zerox1Agent
  private sessions: Map<string, SessionState> = new Map() // Key: agentId
  private completedAgents: Set<string> = new Set() // Key: agentId
  private readonly timeoutMs: number

  constructor(config: GuardianConfig) {
    this.timeoutMs = config.sessionTimeoutMs ?? 60_000

    // Initialize the SDK agent
    this.agent = Zerox1Agent.create({
      keypair: config.keypairPath,
      name: 'GuardianNPC',
      rpcUrl: config.rpcUrl,
      satiMint: config.satiMint,
    })

    // Bind event handlers
    this.agent.on('ADVERTISE', this.handleAdvertise.bind(this))
    this.agent.on('PROPOSE', this.handlePropose.bind(this))
    this.agent.on('DELIVER', this.handleDeliver.bind(this))

    // Start cleanup interval
    setInterval(this.checkTimeouts.bind(this), 10_000)
  }

  /**
   * Start the agent and join the mesh.
   */
  public async start() {
    console.log('🛡️  GuardianNPC starting...')
    await this.agent.start()
    console.log('✅ GuardianNPC is live and listening for new agents.')
  }

  // --------------------------------------------------------------------------
  // Core Quest Logic
  // --------------------------------------------------------------------------

  /**
   * 1. Onboarding: Listen for ADVERTISE broadcasts.
   * If we see a new agent, start a session and send DISCOVER with instructions.
   */
  private async handleAdvertise(env: InboundEnvelope) {
    const agentId = env.sender

    // Ignore if we already have an active session
    if (this.sessions.has(agentId)) return

    // Ignore if agent has already completed the quest
    if (this.completedAgents.has(agentId)) {
        console.log(`ℹ️  Agent ${agentId.slice(0, 8)} already completed the quest. Ignoring.`)
        return
    }

    console.log(`👋 Discovered new agent: ${agentId.slice(0, 8)}...`)

    // Generate a new conversation ID for this quest
    const conversationId = this.agent.newConversationId()

    // Create session state
    this.sessions.set(agentId, {
      agentId,
      conversationId,
      step: 'negotiating', // Expecting a PROPOSE next
      lastActivity: Date.now(),
    })

    // Send DISCOVER with instructions
    // "Welcome to 0x01. To bootstrap your reputation, please send a 'Hello' greeting."
    const instructions = "Welcome to 0x01. To bootstrap your reputation, please send a 'Hello' greeting."
    
    try {
      await this.agent.send({
        msgType: 'DISCOVER',
        recipient: agentId,
        conversationId,
        payload: Buffer.from(instructions),
      })
      console.log(`Pushed quest instructions to ${agentId.slice(0, 8)}...`)
    } catch (err) {
      console.error(`Failed to send DISCOVER to ${agentId}:`, err)
      this.sessions.delete(agentId)
    }
  }

  /**
   * 2. Negotiate: Handle PROPOSE from the new agent.
   * The NPC automatically accepts the proposal (assuming 0 cost for this quest).
   */
  private async handlePropose(env: InboundEnvelope) {
    const session = this.sessions.get(env.sender)
    if (!session) return // Ignore unsolicited proposals
    
    // Check if step is correct
    if (session.step !== 'negotiating') {
      console.log(`❌ Unexpected PROPOSE from ${env.sender.slice(0, 8)}. Expected step: ${session.step}`)
      await this.rejectSession(session, 'Out of order message: Expected negotiating step')
      return
    }

    // Update activity
    session.lastActivity = Date.now()

    console.log(`🤝 Received PROPOSE from ${env.sender.slice(0, 8)}... Auto-accepting.`)

    try {
      // Accept the proposal
      // In a real scenario, we might parse env.payloadB64 to check terms.
      // Here we assume it's the correct "Hello" quest proposal.
      await this.agent.send({
        msgType: 'ACCEPT',
        recipient: env.sender,
        conversationId: session.conversationId,
        payload: Buffer.from('Quest accepted. Waiting for delivery.'),
      })

      // Advance state
      session.step = 'verifying'
    } catch (err) {
      console.error(`Failed to accept proposal from ${env.sender}:`, err)
    }
  }

  /**
   * 3. Verify: Receive DELIVER message.
   * Check if payload contains "Hello". If so, complete quest and reward.
   */
  private async handleDeliver(env: InboundEnvelope) {
    const session = this.sessions.get(env.sender)
    if (!session) return
    
    // Check if step is correct
    if (session.step !== 'verifying') {
      console.log(`❌ Unexpected DELIVER from ${env.sender.slice(0, 8)}. Expected step: ${session.step}`)
      await this.rejectSession(session, 'Out of order message: Expected verifying step')
      return
    }

    session.lastActivity = Date.now()

    // Decode payload
    const payload = Buffer.from(env.payloadB64, 'base64').toString('utf-8')
    console.log(`📦 Received DELIVER from ${env.sender.slice(0, 8)}... Payload: "${payload}"`)

    if (payload.includes('Hello')) {
      console.log(`✅ Quest completed by ${env.sender.slice(0, 8)}! Sending reward...`)
      await this.rewardAgent(session)
    } else {
      console.log(`❌ Invalid delivery from ${env.sender.slice(0, 8)}. Expected "Hello".`)
      await this.rejectSession(session, 'Invalid payload: Expected "Hello"')
    }
  }

  /**
   * 4. Reward: Submit positive FEEDBACK on Solana.
   */
  private async rewardAgent(session: SessionState) {
    try {
      // Reputation +1 (Positive outcome)
      // This is broadcasted to the network and eventually settled on Solana by validators/aggregators.
      await this.agent.sendFeedback({
        conversationId: session.conversationId,
        targetAgent: session.agentId,
        score: 1, // +1 Reputation
        outcome: 'positive',
        role: 'participant', // NPC acted as a participant (client) in this interaction
      })
      
      console.log(`cw Consensus: Feedback submitted for ${session.agentId.slice(0, 8)}...`)
      
      // Mark as completed
      this.completedAgents.add(session.agentId)

      // Quest complete - close session
      this.sessions.delete(session.agentId)
    } catch (err) {
      console.error(`Failed to send feedback for ${session.agentId}:`, err)
    }
  }

  /**
   * Reject a session and clean up.
   */
  private async rejectSession(session: SessionState, reason: string) {
    try {
      await this.agent.send({
        msgType: 'REJECT',
        recipient: session.agentId,
        conversationId: session.conversationId,
        payload: Buffer.from(reason),
      })
    } catch (err) {
      console.error(`Failed to send REJECT to ${session.agentId}:`, err)
    } finally {
      this.sessions.delete(session.agentId)
    }
  }

  // --------------------------------------------------------------------------
  // Utilities
  // --------------------------------------------------------------------------

  /**
   * Periodically clean up stale sessions.
   */
  private checkTimeouts() {
    const now = Date.now()
    for (const [agentId, session] of this.sessions.entries()) {
      if (now - session.lastActivity > this.timeoutMs) {
        console.log(`⏱️  Session timed out for ${agentId.slice(0, 8)}...`)
        this.sessions.delete(agentId)
      }
    }
  }
}

// ============================================================================
// Entrypoint (Example Usage)
// ============================================================================

async function main() {
  const npc = new GuardianNPC({
    keypairPath: './guardian.key', // Ensure this file exists or will be created
    rpcUrl: process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com',
    sessionTimeoutMs: 60_000,
  })

  await npc.start()
}

// Only run if called directly
if (require.main === module) {
  main().catch(err => {
    console.error('Fatal error:', err)
    process.exit(1)
  })
}
