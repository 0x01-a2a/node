import { Zerox1Agent, InboundEnvelope } from '@zerox1/sdk';
import OpenAI from 'openai';
import * as dotenv from 'dotenv';

dotenv.config();

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
});

async function generateResponse(prompt: string) {
    try {
        const completion = await openai.chat.completions.create({
            messages: [{
                role: 'system', content:
                    "You are the 0x01 Mesh Guardian, a friendly NPC designed to help new agents. " +
                    "You speak with a helpful, slightly technical, but welcoming tone. " +
                    "When you see an ADVERTISE broadcast, you should welcome the agent to the mesh. " +
                    "If they are new, explain the 'First Quest': they should send you a PROPOSE with any payload, " +
                    "and once you ACCEPT and they DELIVER, you will give them their first on-chain positive reputation feedback. " +
                    "Keep your responses concise as they are sent over a binary protocol."
            }, { role: 'user', content: prompt }],
            model: 'gpt-3.5-turbo',
            max_tokens: 150,
        });
        return completion.choices[0].message.content;
    } catch (e) {
        return "Welcome to the 0x01 Mesh! I'm the Guardian. Let's start your first quest!";
    }
}

async function run() {
    const agent = Zerox1Agent.create({
        keypair: './guardian.key',
        name: 'Mesh-Guardian',
        satiMint: process.env.GUARDIAN_SATI_MINT, // Optional
    });

    console.log('Guardian NPC starting...');

    // 1. Listen for ADVERTISE broadcasts to find new agents
    agent.on('ADVERTISE', async (env: InboundEnvelope) => {
        console.log(`Saw ADVERTISE from ${env.sender}`);
        const message = await generateResponse(`An agent named ${env.sender.slice(0, 8)} just advertised their capabilities. Send them a warm welcome and mention the First Quest.`);

        // Send DISCOVER greeting
        await agent.send({
            msgType: 'DISCOVER',
            recipient: env.sender,
            conversationId: agent.newConversationId(),
            payload: Buffer.from(message || 'Welcome to the mesh!'),
        });
    });

    // 2. Handle First Quest: PROPOSE
    agent.on('PROPOSE', async (env: InboundEnvelope) => {
        console.log(`Received PROPOSE from ${env.sender}`);
        const message = await generateResponse(`Agent ${env.sender.slice(0, 8)} sent a proposal. Tell them you accept and are looking forward to the delivery.`);

        // Automatically ACCEPT the first quest
        await agent.send({
            msgType: 'ACCEPT',
            recipient: env.sender,
            conversationId: env.conversationId,
            payload: Buffer.from(message || 'Proposal accepted! Send your delivery to complete the quest.'),
        });
    });

    // 3. Handle First Quest: DELIVER
    agent.on('DELIVER', async (env: InboundEnvelope) => {
        console.log(`Received DELIVER from ${env.sender}. Completing quest...`);

        // Send VERDICT (Success)
        await agent.send({
            msgType: 'VERDICT',
            recipient: env.sender,
            conversationId: env.conversationId,
            payload: Buffer.from('VERDICT: SUCCESS. Quest reward: +10 Reputation.'),
        });

        // Provide the reward: Positive Reputation Feedback
        await agent.sendFeedback({
            conversationId: env.conversationId,
            targetAgent: env.sender,
            score: 100, // Max score for onboarding
            outcome: 'positive',
            role: 'participant',
        });

        console.log(`Successfully onboarded agent ${env.sender}`);
    });

    await agent.start();
    console.log('Guardian NPC is live and listening.');
}

run().catch(console.error);
