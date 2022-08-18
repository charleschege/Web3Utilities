use borsh::{BorshDeserialize, BorshSerialize};

/// The total number of items or members required from a list in order to execute or approve a certain task
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, BorshDeserialize, BorshSerialize, Clone, Copy)]
pub enum Threshold {
    /// All the items or members of a list are required to execute or approve a task
    All,
    /// A quarter of the items or members of a list are required to execute or approve a task
    Quarter,
    /// A third of the items or members of a list are required to execute or approve a task
    Third,
    /// A half of the items or members of a list are required to execute or approve a task
    Half,
    /// A two thirds of the items or members of a list are required to execute or approve a task
    TwoThirds,
}

impl Threshold {
    /// Calculate the number of items or members from a list required to approve a certain task.
    pub fn calculate_threshold(&self, group_size: usize) -> usize {
        match self {
            Self::All => group_size,
            Self::Quarter => (group_size as f32 * (1.0 / 4.0)).ceil() as usize,
            Self::Third => (group_size as f32 * (1.0 / 3.0)).ceil() as usize,
            Self::Half => (group_size as f32 * (1.0 / 2.0)).ceil() as usize,
            Self::TwoThirds => (group_size as f32 * (2.0 / 3.0)).ceil() as usize,
        }
    }
}
