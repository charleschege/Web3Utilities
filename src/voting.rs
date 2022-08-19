use core::cmp::Ordering;

use borsh::{BorshDeserialize, BorshSerialize};

/// The tally of the votes cast.
/// #### Structure of the `VoteTally`
/// ```rust
/// pub struct VoteTally {
///     accepted: usize,
///     rejected: usize,
/// }
/// ```
#[derive(Debug, Clone, Copy, BorshDeserialize, BorshSerialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct VoteTally {
    accepted: usize,
    rejected: usize,
}

impl VoteTally {
    /// Instantiate the vote tally
    pub fn new() -> Self {
        VoteTally {
            accepted: 0,
            rejected: 0,
        }
    }

    /// Add an accepted vote
    pub fn accept(&mut self) -> &mut Self {
        self.accepted += 1;

        self
    }

    /// Add a rejected vote
    pub fn reject(&mut self) -> &mut Self {
        self.rejected += 1;

        self
    }

    /// Compile the total of the votes
    pub fn compile(&self) -> (usize, usize) {
        (self.accepted, self.rejected)
    }

    /// Return the outcome of the votes cast
    pub fn outcome(&self) -> VoteOutcome {
        match self.accepted.cmp(&self.rejected) {
            Ordering::Greater => VoteOutcome::Accepted,
            Ordering::Less => VoteOutcome::Rejected,
            Ordering::Equal => VoteOutcome::Equal,
        }
    }
}

impl Default for VoteTally {
    fn default() -> Self {
        VoteTally::new()
    }
}

/// An outcome of an election
#[derive(Debug, Clone, Copy, BorshDeserialize, BorshSerialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum VoteOutcome {
    /// The majority accepted the proposal
    Accepted,
    /// The majority rejected the proposal
    Rejected,
    /// All votes cast were equal
    Equal,
}

/// An instruction to either accept or reject a vote
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum Vote {
    /// Accept a vote
    Accept,
    /// Reject a vote
    Reject,
}

impl Default for Vote {
    fn default() -> Self {
        Vote::Reject
    }
}
