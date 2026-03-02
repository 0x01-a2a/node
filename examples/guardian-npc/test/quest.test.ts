import { describe, it } from 'node:test'
import assert from 'node:assert'
import { GuardianNPC } from '../src/index'
import { Zerox1Agent, InboundEnvelope, SendParams } from '@zerox1/sdk'

// Mock the SDK
const mockSend =  (params: SendParams) => Promise.resolve({ nonce: 1, payloadHash: 'mock' })
const mockSendFeedback =  (params: any) => Promise.resolve({ nonce: 1, payloadHash: 'mock' })
const mockStart =  () => Promise.resolve()
const mockOn =  (type: string, handler: Function) => {
  if (!mockAgent.handlers[type]) mockAgent.handlers[type] = []
  mockAgent.handlers[type].push(handler)
  return mockAgent
}
const mockNewConversationId = () => 'mock-conversation-id'

const mockAgent = {
  handlers: {} as Record<string, Function[]>,
  start: mockStart,
  on: mockOn,
  send: mockSend,
  sendFeedback: mockSendFeedback,
  newConversationId: mockNewConversationId,
}

// Intercept SDK creation
const originalCreate = Zerox1Agent.create
Zerox1Agent.create = () => mockAgent as any

// Helper to simulate incoming messages
async function simulateMessage(npc: any, type: string, sender: string, payload: string, conversationId = 'mock-conversation-id') {
  const handler = mockAgent.handlers[type]?.[0]
  if (handler) {
    await handler({
      msgType: type,
      sender,
      conversationId,
      payloadB64: Buffer.from(payload).toString('base64'),
    } as InboundEnvelope)
  }
}

describe('GuardianNPC Quest Logic', () => {
  const npc = new GuardianNPC({ keypairPath: 'mock.key', sessionTimeoutMs: 1000 })
  
  // Reset mocks before each test
  let sentMessages: any[] = []
  let feedbackSent: any[] = []
  
  mockAgent.send = async (params: any) => {
    sentMessages.push(params)
    return { nonce: 1, payloadHash: 'mock' }
  }
  
  mockAgent.sendFeedback = async (params: any) => {
    feedbackSent.push(params)
    return { nonce: 1, payloadHash: 'mock' }
  }

  it('Scenario 1: Standard Path (Happy Flow)', async () => {
    const agentId = 'agent-standard'
    
    // 1. ADVERTISE
    await simulateMessage(npc, 'ADVERTISE', agentId, '')
    assert.strictEqual(sentMessages.length, 1)
    assert.strictEqual(sentMessages[0].msgType, 'DISCOVER')
    assert.match(sentMessages[0].payload.toString(), /Welcome/)

    // 2. PROPOSE
    await simulateMessage(npc, 'PROPOSE', agentId, 'some proposal')
    assert.strictEqual(sentMessages.length, 2)
    assert.strictEqual(sentMessages[1].msgType, 'ACCEPT')

    // 3. DELIVER "Hello"
    await simulateMessage(npc, 'DELIVER', agentId, 'Hello world')
    
    // Should trigger reward
    assert.strictEqual(feedbackSent.length, 1)
    assert.strictEqual(feedbackSent[0].targetAgent, agentId)
    assert.strictEqual(feedbackSent[0].score, 1)
  })

  it('Scenario 2: Wrong Content (Goodbye instead of Hello)', async () => {
    const agentId = 'agent-wrong-content'
    sentMessages = []
    feedbackSent = []

    // 1. ADVERTISE
    await simulateMessage(npc, 'ADVERTISE', agentId, '')
    
    // 2. PROPOSE
    await simulateMessage(npc, 'PROPOSE', agentId, 'proposal')

    // 3. DELIVER "Goodbye"
    await simulateMessage(npc, 'DELIVER', agentId, 'Goodbye world')

    // Should receive REJECT
    assert.strictEqual(sentMessages.length, 3) // DISCOVER + ACCEPT + REJECT
    assert.strictEqual(sentMessages[2].msgType, 'REJECT')
    
    // Should NOT trigger reward
    assert.strictEqual(feedbackSent.length, 0)
  })

  it('Scenario 3: Out of Order (Skip PROPOSE)', async () => {
    const agentId = 'agent-out-of-order'
    sentMessages = []
    feedbackSent = []

    // 1. ADVERTISE (Starts session, step = negotiating)
    await simulateMessage(npc, 'ADVERTISE', agentId, '')

    // 2. DELIVER directly (Skip PROPOSE)
    // NPC expects step 'verifying', but current is 'negotiating'
    await simulateMessage(npc, 'DELIVER', agentId, 'Hello')

    // Should receive REJECT
    assert.strictEqual(sentMessages.length, 2) // DISCOVER + REJECT
    assert.strictEqual(sentMessages[1].msgType, 'REJECT')

    // Should be ignored
    assert.strictEqual(feedbackSent.length, 0)
  })

  it('Scenario 4: Duplicate Identity (Double Dipping)', async () => {
    const agentId = 'agent-double-dip'
    sentMessages = []
    feedbackSent = []

    // --- First Run (Success) ---
    await simulateMessage(npc, 'ADVERTISE', agentId, '')
    await simulateMessage(npc, 'PROPOSE', agentId, '')
    await simulateMessage(npc, 'DELIVER', agentId, 'Hello')
    
    assert.strictEqual(feedbackSent.length, 1) // First reward given
    
    // Session is deleted after reward.
    // If we want to prevent double dipping, we need persistent storage.
    // The current implementation deletes the session, so a new ADVERTISE *will* start a new session.
    // Let's verify current behavior:
    
    await simulateMessage(npc, 'ADVERTISE', agentId, '')
    assert.strictEqual(sentMessages.length, 2) // Should NOT send new DISCOVER
    
    // Current implementation allows retrying if session is gone.
    // To fix "Identity Duplicate", we would need a 'completedAgents' Set.
  })

  it('Scenario 5: Concurrency Stress Test (10 agents)', async () => {
    sentMessages = []
    feedbackSent = []
    
    const startTime = Date.now()
    const agentCount = 10
    const agents = Array.from({ length: agentCount }, (_, i) => `stress-agent-${i}`)
    
    // Simulate concurrent workflows
    await Promise.all(agents.map(async (agentId) => {
        // 1. ADVERTISE
        await simulateMessage(npc, 'ADVERTISE', agentId, '')
        
        // 2. PROPOSE
        await simulateMessage(npc, 'PROPOSE', agentId, 'proposal')
        
        // 3. DELIVER "Hello"
        await simulateMessage(npc, 'DELIVER', agentId, 'Hello world')
    }))
    
    const duration = Date.now() - startTime
    console.log(`\n⚡ Concurrency Test: Processed ${agentCount} agents in ${duration}ms`)

    // Verify all agents got rewarded
    assert.strictEqual(feedbackSent.length, agentCount)
    
    // Verify rewards are correctly attributed
    const rewardedAgents = new Set(feedbackSent.map(f => f.targetAgent))
    assert.strictEqual(rewardedAgents.size, agentCount)
    agents.forEach(agentId => {
        assert.ok(rewardedAgents.has(agentId), `Agent ${agentId} missed reward`)
    })
  })
})
