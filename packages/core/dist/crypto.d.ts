/**
 * Ed25519 keypair generation and signing — wraps @noble/ed25519.
 *
 * Agent identity on the 0x01 mesh is a 32-byte Ed25519 public key,
 * represented as a 64-char lowercase hex string (agent_id).
 */
export interface Keypair {
    /** 32-byte raw private key scalar */
    privateKey: Uint8Array;
    /** 32-byte Ed25519 public key (= agent_id bytes) */
    publicKey: Uint8Array;
}
/** Generate a new random Ed25519 keypair. */
export declare function generateKeypair(): Promise<Keypair>;
/**
 * Derive a keypair deterministically from a 32-byte seed.
 * Useful for reproducible identities from a stored secret.
 */
export declare function keypairFromSeed(seed: Uint8Array): Promise<Keypair>;
/** Sign a message with a private key. Returns a 64-byte signature. */
export declare function sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
/** Verify a signature against a message and public key. */
export declare function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
/** Convert a 32-byte public key to a 64-char lowercase hex agent_id. */
export declare function publicKeyToAgentId(publicKey: Uint8Array): string;
/** Parse a 64-char hex agent_id back to 32-byte public key bytes. */
export declare function agentIdToPublicKey(agentId: string): Uint8Array;
//# sourceMappingURL=crypto.d.ts.map