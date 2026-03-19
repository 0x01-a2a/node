"use strict";
/**
 * Ed25519 keypair generation and signing — wraps @noble/ed25519.
 *
 * Agent identity on the 0x01 mesh is a 32-byte Ed25519 public key,
 * represented as a 64-char lowercase hex string (agent_id).
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateKeypair = generateKeypair;
exports.keypairFromSeed = keypairFromSeed;
exports.sign = sign;
exports.verify = verify;
exports.publicKeyToAgentId = publicKeyToAgentId;
exports.agentIdToPublicKey = agentIdToPublicKey;
const ed = __importStar(require("@noble/ed25519"));
/** Generate a new random Ed25519 keypair. */
async function generateKeypair() {
    const privateKey = ed.utils.randomPrivateKey();
    const publicKey = await ed.getPublicKeyAsync(privateKey);
    return { privateKey, publicKey };
}
/**
 * Derive a keypair deterministically from a 32-byte seed.
 * Useful for reproducible identities from a stored secret.
 */
async function keypairFromSeed(seed) {
    if (seed.length !== 32)
        throw new Error('Seed must be 32 bytes');
    const publicKey = await ed.getPublicKeyAsync(seed);
    return { privateKey: seed, publicKey };
}
/** Sign a message with a private key. Returns a 64-byte signature. */
async function sign(message, privateKey) {
    return ed.signAsync(message, privateKey);
}
/** Verify a signature against a message and public key. */
async function verify(signature, message, publicKey) {
    try {
        return await ed.verifyAsync(signature, message, publicKey);
    }
    catch {
        return false;
    }
}
/** Convert a 32-byte public key to a 64-char lowercase hex agent_id. */
function publicKeyToAgentId(publicKey) {
    return Buffer.from(publicKey).toString('hex');
}
/** Parse a 64-char hex agent_id back to 32-byte public key bytes. */
function agentIdToPublicKey(agentId) {
    if (agentId.length !== 64)
        throw new Error('agent_id must be 64 hex chars');
    return Buffer.from(agentId, 'hex');
}
//# sourceMappingURL=crypto.js.map