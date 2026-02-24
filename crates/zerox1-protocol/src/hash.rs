use tiny_keccak::{Hasher, Keccak};

/// Keccak-256 hash of the input bytes.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Merkle tree over a slice of leaf data blobs.
///
/// - Leaf hash:     keccak256(canonical_cbor_encode(entry))
/// - Internal hash: keccak256(left || right)
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
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&chunk[0]);
            combined[32..].copy_from_slice(&chunk[1]);
            next.push(keccak256(&combined));
        }
        layer = next;
    }

    layer[0]
}

/// Verify a merkle inclusion proof.
///
/// `leaf_hash`  — keccak256 of the leaf data
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
        let mut combined = [0u8; 64];
        if idx % 2 == 0 {
            combined[..32].copy_from_slice(&current);
            combined[32..].copy_from_slice(sibling);
        } else {
            combined[..32].copy_from_slice(sibling);
            combined[32..].copy_from_slice(&current);
        }
        current = keccak256(&combined);
        idx /= 2;
    }

    current == root
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
        let leaf = keccak256(b"hello");
        assert_eq!(merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn two_leaf_root() {
        let a = keccak256(b"a");
        let b = keccak256(b"b");
        let root = merkle_root(&[a, b]);

        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&a);
        combined[32..].copy_from_slice(&b);
        let expected = keccak256(&combined);

        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_proof_verification() {
        let leaves: Vec<[u8; 32]> = (0u8..4).map(|i| keccak256(&[i])).collect();
        let root = merkle_root(&leaves);

        // Proof for leaf 0: sibling is leaf 1, then hash(leaf2||leaf3)
        let sibling_01 = leaves[1];
        let mut c23 = [0u8; 64];
        c23[..32].copy_from_slice(&leaves[2]);
        c23[32..].copy_from_slice(&leaves[3]);
        let hash_23 = keccak256(&c23);

        assert!(verify_merkle_proof(leaves[0], &[sibling_01, hash_23], 0, root));
        assert!(!verify_merkle_proof(leaves[0], &[sibling_01, hash_23], 1, root));
    }
}
