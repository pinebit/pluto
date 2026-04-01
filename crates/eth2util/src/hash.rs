use pluto_eth2api::spec::phase0::{Root, Slot};
use pluto_ssz::{HashWalker, Hasher, HasherError};

/// Hashing error.
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    /// Failed to hash the slot root.
    #[error("hash epoch: {0}")]
    HashEpoch(#[from] HasherError),
}

/// Result type for hash helpers.
type Result<T> = std::result::Result<T, HashError>;

/// Returns the SSZ hash root of the slot.
pub fn slot_hash_root(slot: Slot) -> Result<Root> {
    let mut hasher = Hasher::default();
    let index = hasher.index();

    hasher.put_uint64(slot)?;
    hasher.merkleize(index)?;

    Ok(hasher.hash_root()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_hash_root() {
        let resp = slot_hash_root(2).expect("hash slot");
        assert_eq!(
            hex::encode(resp),
            "0200000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
