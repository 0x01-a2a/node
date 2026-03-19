/**
 * Ed25519 keypair generation and signing — wraps @noble/ed25519.
 *
 * Agent identity on the 0x01 mesh is a 32-byte Ed25519 public key,
 * represented as a 64-char lowercase hex string (agent_id).
 */

import * as ed from '@noble/ed25519'

export interface Keypair {
  /** 32-byte raw private key scalar */
  privateKey: Uint8Array
  /** 32-byte Ed25519 public key (= agent_id bytes) */
  publicKey: Uint8Array
}

/** Generate a new random Ed25519 keypair. */
export async function generateKeypair(): Promise<Keypair> {
  const privateKey = ed.utils.randomPrivateKey()
  const publicKey = await ed.getPublicKeyAsync(privateKey)
  return { privateKey, publicKey }
}

/**
 * Derive a keypair deterministically from a 32-byte seed.
 * Useful for reproducible identities from a stored secret.
 */
export async function keypairFromSeed(seed: Uint8Array): Promise<Keypair> {
  if (seed.length !== 32) throw new Error('Seed must be 32 bytes')
  const publicKey = await ed.getPublicKeyAsync(seed)
  return { privateKey: seed, publicKey }
}

/** Sign a message with a private key. Returns a 64-byte signature. */
export async function sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  return ed.signAsync(message, privateKey)
}

/** Verify a signature against a message and public key. */
export async function verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  try {
    return await ed.verifyAsync(signature, message, publicKey)
  } catch {
    return false
  }
}

/** Convert a 32-byte public key to a 64-char lowercase hex agent_id. */
export function publicKeyToAgentId(publicKey: Uint8Array): string {
  return Buffer.from(publicKey).toString('hex')
}

/** Parse a 64-char hex agent_id back to 32-byte public key bytes. */
export function agentIdToPublicKey(agentId: string): Uint8Array {
  if (agentId.length !== 64) throw new Error('agent_id must be 64 hex chars')
  return Buffer.from(agentId, 'hex')
}
