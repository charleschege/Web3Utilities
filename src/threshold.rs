use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, BorshDeserialize, BorshSerialize, Clone, Copy)]
pub enum Threshold {
    All,
    Quarter,
    Third,
    Half,
    TwoThirds,
}

impl Threshold {
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
