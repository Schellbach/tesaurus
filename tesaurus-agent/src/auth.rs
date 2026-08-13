//! Fail-closed transport authentication.
//!
//! The SignRequest MAC / signature scheme is not specified enough to verify.
//! Production construction always yields a rejected [`AgentAuth`]. There is no
//! `auth_ok: bool` and no way to mark verified. Leftover: local MAC check
//! (`verified_by_this_agent`) with the `--via-agent` unlock.

use tesaurus_policy::AgentAuth;

/// Production constructor: transport MAC is unspecified, so auth never succeeds.
///
/// Callers must not treat this as a co-sign gate they can flip. Pass the mark
/// to `evaluate`; it will reject with `AUTH`.
pub fn agent_auth_from_unspecified_mac() -> AgentAuth {
    AgentAuth::from_agent_tcb_mac_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{chain_view_from_core_b, empty_regtest_core};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Network, PublicKey};
    use tesaurus_policy::{evaluate, AgentPin, PolicyErrorCode, PolicyRequest, ReplayStore};

    fn pk(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut buf = [seed; 32];
        buf[31] = seed.wrapping_add(3);
        let sk = SecretKey::from_slice(&buf).unwrap();
        PublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(sk, Network::Regtest))
    }

    #[test]
    fn unspecified_mac_is_fail_closed_auth() {
        let pin = AgentPin::provision(Network::Regtest, pk(1), pk(2), pk(3), 10).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let store = ReplayStore::init(tmp.path()).unwrap();
        let chain = chain_view_from_core_b(&empty_regtest_core(&pin), &[], 0).unwrap();
        let err = evaluate(
            &pin,
            &PolicyRequest {
                request_id: [0u8; 16],
                psbt_bytes: b"not-a-psbt",
                confirm_token: None,
                claimed_external_sats: 1,
            },
            agent_auth_from_unspecified_mac(),
            &chain,
            &store,
            &[],
        )
        .unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::Auth);
    }
}
