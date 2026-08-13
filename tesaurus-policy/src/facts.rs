//! Caller-supplied Core B facts and agent-local auth marks.
//!
//! `evaluate` taking these as inputs is the right split for a pure crate: policy
//! never opens RPC or verifies a transport MAC. A lying caller can fake CSV
//! maturity, `visible_unspent`, and `FOREIGN_INPUT`. **Policy cannot defend
//! against that.** The TCB is whoever builds [`ChainView`] / [`AgentAuth`].
//!
//! **Tests may lie; production must not.**
//!
//! There is no public struct-literal for [`ChainView`] or [`PrevoutFact`], and
//! no `ChainView::from_core_b` yet (live Core B RPC is leftover in
//! `tesaurus-agent`). The only constructors are `#[cfg(test)]` and are named
//! `from_test_facts` so a future agent cannot accidentally pass coordinator
//! metadata through.
//!
//! [`AgentAuth`] is not a `bool`. There is no production constructor until the
//! agent verifies a transport MAC locally. Tests use
//! [`AgentAuth::for_test_verified`] / [`AgentAuth::for_test_rejected`]. A
//! coordinator-supplied flag cannot be forwarded.

use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf};

/// Opaque mark that transport authentication succeeded **in this agent**.
///
/// Do not reconstruct this from a coordinator field. Production construction
/// (`verified_by_this_agent` after a local MAC check) is leftover with the
/// auth-MAC / `--via-agent` unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentAuth {
    ok: bool,
}

impl AgentAuth {
    pub(crate) fn is_ok(self) -> bool {
        self.ok
    }

    /// Test-only: pretend the agent verified auth. Production must not call this.
    #[cfg(test)]
    pub fn for_test_verified() -> Self {
        Self { ok: true }
    }

    /// Test-only: pretend auth failed.
    #[cfg(test)]
    pub fn for_test_rejected() -> Self {
        Self { ok: false }
    }
}

/// Independent-chain facts for §6.4 / §6.3b.
///
/// Fields are private so production code cannot write
/// `ChainView { visible_unspent: true, .. }` from coordinator claims.
#[derive(Debug, Clone)]
pub struct ChainView {
    genesis_hash: BlockHash,
    tip_height: u32,
    now_unix: u64,
    prevouts: Vec<PrevoutFact>,
}

impl ChainView {
    pub fn genesis_hash(&self) -> BlockHash {
        self.genesis_hash
    }

    pub fn tip_height(&self) -> u32 {
        self.tip_height
    }

    pub fn now_unix(&self) -> u64 {
        self.now_unix
    }

    pub fn prevouts(&self) -> &[PrevoutFact] {
        &self.prevouts
    }

    /// Test-only constructor. **May lie** about CSV, unspent, scripts, and time.
    ///
    /// Production must not use this. When Core B RPC lands, add
    /// `ChainView::from_core_b(...)` that fills these fields from bitcoind, not
    /// from the coordinator.
    #[cfg(test)]
    pub fn from_test_facts(
        genesis_hash: BlockHash,
        tip_height: u32,
        now_unix: u64,
        prevouts: Vec<PrevoutFact>,
    ) -> Self {
        Self {
            genesis_hash,
            tip_height,
            now_unix,
            prevouts,
        }
    }

    /// Test-only: lie about tip height (CSV depth).
    #[cfg(test)]
    pub fn with_test_tip_height(mut self, tip_height: u32) -> Self {
        self.tip_height = tip_height;
        self
    }

    /// Test-only: replace one prevout script (FOREIGN_INPUT fixtures).
    #[cfg(test)]
    pub fn with_test_prevout_script(mut self, index: usize, script_pubkey: ScriptBuf) -> Self {
        self.prevouts[index].script_pubkey = script_pubkey;
        self
    }
}

/// One Core B prevout fact. Private fields: tests may lie; production must not.
#[derive(Debug, Clone)]
pub struct PrevoutFact {
    outpoint: OutPoint,
    value: Amount,
    script_pubkey: ScriptBuf,
    confirm_height: u32,
    header_time_unix: u64,
    visible_unspent: bool,
}

impl PrevoutFact {
    pub fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    pub fn value(&self) -> Amount {
        self.value
    }

    pub fn script_pubkey(&self) -> &ScriptBuf {
        &self.script_pubkey
    }

    pub fn confirm_height(&self) -> u32 {
        self.confirm_height
    }

    pub fn header_time_unix(&self) -> u64 {
        self.header_time_unix
    }

    pub fn visible_unspent(&self) -> bool {
        self.visible_unspent
    }

    /// Test-only constructor. **May lie** (`visible_unspent`, amounts, scripts).
    #[cfg(test)]
    pub fn from_test_facts(
        outpoint: OutPoint,
        value: Amount,
        script_pubkey: ScriptBuf,
        confirm_height: u32,
        header_time_unix: u64,
        visible_unspent: bool,
    ) -> Self {
        Self {
            outpoint,
            value,
            script_pubkey,
            confirm_height,
            header_time_unix,
            visible_unspent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, ScriptBuf};

    #[test]
    fn test_constructors_are_the_only_way_to_build_lying_views() {
        // Production has no from_core_b and no public fields. This named
        // constructor is how tests lie; a future agent must not call it.
        let view = ChainView::from_test_facts(
            BlockHash::from_byte_array([0u8; 32]),
            1,
            0,
            vec![PrevoutFact::from_test_facts(
                bitcoin::OutPoint::null(),
                Amount::from_sat(1),
                ScriptBuf::new(),
                1,
                0,
                true,
            )],
        );
        assert!(view.prevouts()[0].visible_unspent());
        assert!(AgentAuth::for_test_verified().is_ok());
        assert!(!AgentAuth::for_test_rejected().is_ok());
    }
}
