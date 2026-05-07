//! Epoch management for replay protection.

use std::collections::HashMap;

/// Tracks the latest epoch per group.
pub struct EpochManager {
    epochs: HashMap<Vec<u8>, u64>,
}

impl EpochManager {
    /// Create a new epoch manager.
    pub fn new() -> Self {
        Self {
            epochs: HashMap::new(),
        }
    }

    /// Validate that the given epoch is newer than the current one.
    pub fn validate(&self, group_id: &[u8], epoch: u64) -> bool {
        match self.epochs.get(group_id) {
            Some(current) => epoch > *current,
            None => true,
        }
    }

    /// Advance the epoch for a group.
    pub fn advance(&mut self, group_id: Vec<u8>, epoch: u64) {
        self.epochs.insert(group_id, epoch);
    }
}

impl Default for EpochManager {
    fn default() -> Self {
        Self::new()
    }
}
