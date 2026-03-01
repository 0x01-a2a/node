use tiny_keccak::{Hasher, Keccak};
const MERKLE_LEAF_DOMAIN: u8 = 0x00;
const MERKLE_INTERNAL_DOMAIN: u8 = 0x01;

/// Keccak-256 hash of the input bytes.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Domain-separated Merkle leaf hash: keccak256(0x00 || leaf_bytes).
pub fn hash_merkle_leaf(leaf_bytes: &[u8]) -> [u8; 32] {
    let mut prefixed = Vec::with_capacity(1 + leaf_bytes.len());
    prefixed.push(MERKLE_LEAF_DOMAIN);
    prefixed.extend_from_slice(leaf_bytes);
    keccak256(&prefixed)
}

/// Merkle tree over a slice of leaf data blobs.
///
/// - Leaf hash:     keccak256(0x00 || canonical_cbor_encode(entry))
/// - Internal hash: keccak256(0x01 || left || right)
/// - Non-power-of-2 counts are padded with zero-hashes on the right.
///
/// Returns the 32-byte merkle root, or [0u8; 32] for an empty input.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    // Round up to next power of two, pad with zero hashes.
    let n = leaves.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(n);
    layer.extend_from_slice(leaves);
    layer.resize(n, [0u8; 32]);

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks_exact(2) {
            next.push(hash_internal_nodes(chunk[0], chunk[1]));
        }
        layer = next;
    }

    layer[0]
}

/// Verify a merkle inclusion proof.
///
/// `leaf_hash`  — keccak256(0x00 || leaf data)
/// `proof`      — sibling hashes from leaf to root
/// `index`      — 0-based leaf index
/// `root`       — expected root
pub fn verify_merkle_proof(
    leaf_hash: [u8; 32],
    proof: &[[u8; 32]],
    index: usize,
    root: [u8; 32],
) -> bool {
    let mut current = leaf_hash;
    let mut idx = index;

    for sibling in proof {
        if idx.is_multiple_of(2) {
            current = hash_internal_nodes(current, *sibling);
        } else {
            current = hash_internal_nodes(*sibling, current);
        }
        idx /= 2;
    }

    current == root
}

fn hash_internal_nodes(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 65];
    combined[0] = MERKLE_INTERNAL_DOMAIN;
    combined[1..33].copy_from_slice(&left);
    combined[33..65].copy_from_slice(&right);
    keccak256(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_merkle_root_is_zero() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn single_leaf_root_equals_leaf() {
        let leaf = hash_merkle_leaf(b"hello");
        assert_eq!(merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn two_leaf_root() {
        let a = hash_merkle_leaf(b"a");
        let b = hash_merkle_leaf(b"b");
        let root = merkle_root(&[a, b]);

        let expected = hash_internal_nodes(a, b);

        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_proof_verification() {
        let leaves: Vec<[u8; 32]> = (0u8..4).map(|i| hash_merkle_leaf(&[i])).collect();
        let root = merkle_root(&leaves);

        // Proof for leaf 0: sibling is leaf 1, then hash(leaf2||leaf3)
        let sibling_01 = leaves[1];
        let hash_23 = hash_internal_nodes(leaves[2], leaves[3]);

        assert!(verify_merkle_proof(
            leaves[0],
            &[sibling_01, hash_23],
            0,
            root
        ));
        assert!(!verify_merkle_proof(
            leaves[0],
            &[sibling_01, hash_23],
            1,
            root
        ));
    }
}
