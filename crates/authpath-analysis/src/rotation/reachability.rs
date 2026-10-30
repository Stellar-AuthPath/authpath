//! Whether explicitly declared-available signers can still authorize, per
//! threshold.
//!
//! Reachability compares weight against thresholds; it never counts signers.
//! A low signer count is not a lockout when the available weight still meets
//! the thresholds, and a high signer count is not safe when the available
//! weight does not. A configured signer contributes only when both the
//! account-state availability declaration and the plan-wide identity set say
//! it is available.

use authpath_model::{AccountId, AccountSnapshot};

use crate::{
    AnalysisError, AvailableSigners, ThresholdCategory, available_weight, required_weight,
};

/// Whether a threshold can be met, and by whom.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReachStatus {
    /// The declared-available signers meet the threshold.
    Reachable,
    /// The declared-available signers fall short, but the account's full
    /// configured weight, including signers declared unavailable, would meet
    /// it. Restoring a credential could recover the capability.
    RequiresUnavailableSigners,
    /// Even every configured signer together cannot meet the threshold (or
    /// no signer has positive weight), so no key set can authorize.
    Unreachable,
}

/// Reachability of one threshold category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LevelReach {
    threshold: ThresholdCategory,
    required_weight: u64,
    available_weight: u64,
    configured_weight: u64,
    status: ReachStatus,
}

impl LevelReach {
    /// Returns the threshold category.
    #[must_use]
    pub const fn threshold(&self) -> ThresholdCategory {
        self.threshold
    }

    /// Returns the configured threshold value.
    #[must_use]
    pub const fn required_weight(&self) -> u64 {
        self.required_weight
    }

    /// Returns the weight of declared-available signers.
    #[must_use]
    pub const fn available_weight(&self) -> u64 {
        self.available_weight
    }

    /// Returns the weight of every configured signer and a non-zero master key.
    #[must_use]
    pub const fn configured_weight(&self) -> u64 {
        self.configured_weight
    }

    /// Returns the reachability status.
    #[must_use]
    pub const fn status(&self) -> ReachStatus {
        self.status
    }

    /// Reports whether declared-available signers meet the threshold.
    #[must_use]
    pub const fn is_reachable(&self) -> bool {
        matches!(self.status, ReachStatus::Reachable)
    }
}

/// Reachability of all three threshold categories for one account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountReach {
    account: AccountId,
    low: LevelReach,
    medium: LevelReach,
    high: LevelReach,
}

impl AccountReach {
    /// Returns the account.
    #[must_use]
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// Returns low-threshold reachability (transaction source checks).
    #[must_use]
    pub const fn low(&self) -> LevelReach {
        self.low
    }

    /// Returns medium-threshold reachability.
    #[must_use]
    pub const fn medium(&self) -> LevelReach {
        self.medium
    }

    /// Returns high-threshold reachability (signer, threshold and master
    /// weight changes).
    #[must_use]
    pub const fn high(&self) -> LevelReach {
        self.high
    }

    /// Returns the reachability of a threshold category.
    #[must_use]
    pub const fn level(&self, threshold: ThresholdCategory) -> LevelReach {
        match threshold {
            ThresholdCategory::Low => self.low,
            ThresholdCategory::Medium => self.medium,
            ThresholdCategory::High => self.high,
        }
    }

    /// Reports whether the account's own configuration can still be changed
    /// by declared-available signers.
    #[must_use]
    pub const fn can_administer(&self) -> bool {
        self.high.is_reachable()
    }
}

/// Why an account has lost, or never had, administrative reach.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockoutKind {
    /// The high threshold needs signers declared unavailable.
    HighThresholdRequiresUnavailableSigners,
    /// No set of configured signers can ever meet the high threshold; this
    /// state is permanent unless the model is missing signers.
    HighThresholdUnreachable,
    /// High is reachable, but the low threshold, which the account needs as
    /// its own transaction source, is not. Administration would require a
    /// different transaction source account.
    LowThresholdNotReachable {
        /// Whether no configured signer set could meet it.
        permanent: bool,
    },
}

impl AccountReach {
    /// Reports how administrative reach is lost, or `None` if it holds.
    #[must_use]
    pub const fn lockout(&self) -> Option<LockoutKind> {
        match self.high.status {
            ReachStatus::RequiresUnavailableSigners => {
                Some(LockoutKind::HighThresholdRequiresUnavailableSigners)
            }
            ReachStatus::Unreachable => Some(LockoutKind::HighThresholdUnreachable),
            ReachStatus::Reachable => match self.low.status {
                ReachStatus::Reachable => None,
                ReachStatus::RequiresUnavailableSigners => {
                    Some(LockoutKind::LowThresholdNotReachable { permanent: false })
                }
                ReachStatus::Unreachable => {
                    Some(LockoutKind::LowThresholdNotReachable { permanent: true })
                }
            },
        }
    }
}

/// Computes threshold reachability for an account configuration.
///
/// A threshold is met only by positive weight, because stellar-core requires
/// a matching signer even when a threshold is zero.
pub fn account_reach(
    snapshot: &AccountSnapshot,
    available: &AvailableSigners,
) -> Result<AccountReach, AnalysisError> {
    let configured = configured_weight(snapshot)?;
    let available_total = available_weight(snapshot, available)?;
    let level = |threshold| {
        let required = required_weight(snapshot, threshold);
        let status = if available_total >= required && available_total > 0 {
            ReachStatus::Reachable
        } else if configured >= required && configured > 0 {
            ReachStatus::RequiresUnavailableSigners
        } else {
            ReachStatus::Unreachable
        };
        LevelReach {
            threshold,
            required_weight: required,
            available_weight: available_total,
            configured_weight: configured,
            status,
        }
    };

    Ok(AccountReach {
        account: *snapshot.account_id(),
        low: level(ThresholdCategory::Low),
        medium: level(ThresholdCategory::Medium),
        high: level(ThresholdCategory::High),
    })
}

fn configured_weight(snapshot: &AccountSnapshot) -> Result<u64, AnalysisError> {
    snapshot
        .signers()
        .iter()
        .try_fold(
            u64::from(snapshot.master_key_weight().value()),
            |total, signer| total.checked_add(u64::from(signer.weight().value())),
        )
        .ok_or(AnalysisError::WeightOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use authpath_model::{
        ConfiguredSigner, Ed25519PublicKey, MasterKeyWeight, NetworkIdentity, SignerAvailability,
        SignerWeight, SnapshotProvenance, Thresholds,
    };

    fn key(seed: u8) -> Ed25519PublicKey {
        Ed25519PublicKey::from_bytes([seed; 32])
    }

    fn snapshot(
        master: u8,
        thresholds: (u32, u32, u32),
        signers: &[(u8, u8, SignerAvailability)],
    ) -> AccountSnapshot {
        AccountSnapshot::new(
            AccountId::from_bytes([1; 32]),
            MasterKeyWeight::from_u8(master),
            Thresholds::new(thresholds.0, thresholds.1, thresholds.2).unwrap(),
            signers
                .iter()
                .map(|&(seed, weight, availability)| {
                    ConfiguredSigner::new(key(seed), SignerWeight::from_u8(weight), availability)
                })
                .collect(),
            SnapshotProvenance::caller_provided(Some(NetworkIdentity::new("fixture").unwrap())),
        )
        .unwrap()
    }

    const AVAILABLE: SignerAvailability = SignerAvailability::Available;
    const UNAVAILABLE: SignerAvailability = SignerAvailability::Unavailable;

    #[test]
    fn a_single_sufficient_signer_is_reachable_without_redundancy() {
        // One signer is enough when its weight meets every threshold.
        let reach = account_reach(
            &snapshot(1, (1, 1, 1), &[]),
            &AvailableSigners::new([key(1)]),
        )
        .unwrap();
        assert!(reach.can_administer());
        assert_eq!(reach.lockout(), None);
    }

    #[test]
    fn many_signers_do_not_help_when_available_weight_is_short() {
        // Three configured signers of weight 1, high threshold 3, but only
        // two are available: 2 < 3.
        let account = snapshot(
            0,
            (1, 1, 3),
            &[(2, 1, AVAILABLE), (3, 1, AVAILABLE), (4, 1, UNAVAILABLE)],
        );
        let reach =
            account_reach(&account, &AvailableSigners::new([key(2), key(3), key(4)])).unwrap();
        assert_eq!(reach.high().available_weight(), 2);
        assert_eq!(reach.high().configured_weight(), 3);
        assert_eq!(
            reach.high().status(),
            ReachStatus::RequiresUnavailableSigners
        );
        assert_eq!(
            reach.lockout(),
            Some(LockoutKind::HighThresholdRequiresUnavailableSigners)
        );
        // The lower thresholds are still met.
        assert!(reach.low().is_reachable());
        assert!(reach.medium().is_reachable());
    }

    #[test]
    fn a_threshold_above_total_configured_weight_is_permanently_unreachable() {
        // Master 1 + signer 2 = 3 in total, high threshold 4, all available.
        let account = snapshot(1, (1, 1, 4), &[(2, 2, AVAILABLE)]);
        let reach = account_reach(&account, &AvailableSigners::new([key(1), key(2)])).unwrap();
        assert_eq!(reach.high().available_weight(), 3);
        assert_eq!(reach.high().status(), ReachStatus::Unreachable);
        assert_eq!(reach.lockout(), Some(LockoutKind::HighThresholdUnreachable));
    }

    #[test]
    fn exact_equality_is_reachable_and_one_below_is_not() {
        let at = account_reach(
            &snapshot(2, (1, 1, 2), &[]),
            &AvailableSigners::new([key(1)]),
        )
        .unwrap();
        assert!(at.high().is_reachable());
        let below = account_reach(
            &snapshot(1, (1, 1, 2), &[]),
            &AvailableSigners::new([key(1)]),
        )
        .unwrap();
        assert_eq!(below.high().status(), ReachStatus::Unreachable);
    }

    #[test]
    fn a_disabled_master_key_with_no_signers_is_unreachable_even_at_threshold_zero() {
        // stellar-core omits a zero-weight master key from the signer list,
        // so nothing can match a signature.
        let reach = account_reach(
            &snapshot(0, (0, 0, 0), &[]),
            &AvailableSigners::new([key(1)]),
        )
        .unwrap();
        assert_eq!(reach.high().status(), ReachStatus::Unreachable);
        assert_eq!(reach.low().status(), ReachStatus::Unreachable);
        assert_eq!(reach.lockout(), Some(LockoutKind::HighThresholdUnreachable));
    }

    #[test]
    fn master_key_counts_only_when_its_identity_is_declared_available() {
        let account = snapshot(1, (1, 1, 1), &[]);
        let reach = account_reach(&account, &AvailableSigners::new([key(9)])).unwrap();
        assert_eq!(
            reach.high().status(),
            ReachStatus::RequiresUnavailableSigners
        );
    }

    #[test]
    fn a_signer_flagged_unavailable_does_not_count_even_if_its_key_is_declared() {
        let account = snapshot(0, (1, 1, 1), &[(2, 5, UNAVAILABLE)]);
        let reach = account_reach(&account, &AvailableSigners::new([key(2)])).unwrap();
        assert_eq!(reach.high().available_weight(), 0);
        assert_eq!(
            reach.high().status(),
            ReachStatus::RequiresUnavailableSigners
        );
    }

    #[test]
    fn an_unreachable_low_threshold_limits_self_sourced_administration() {
        // High threshold 2 is met by weight 2, but low threshold 3 is not and
        // the account has no more weight to give.
        let account = snapshot(2, (3, 1, 2), &[]);
        let reach = account_reach(&account, &AvailableSigners::new([key(1)])).unwrap();
        assert!(reach.can_administer());
        assert_eq!(
            reach.lockout(),
            Some(LockoutKind::LowThresholdNotReachable { permanent: true })
        );

        let recoverable = snapshot(2, (3, 1, 2), &[(2, 1, UNAVAILABLE)]);
        let reach = account_reach(&recoverable, &AvailableSigners::new([key(1), key(2)])).unwrap();
        assert_eq!(
            reach.lockout(),
            Some(LockoutKind::LowThresholdNotReachable { permanent: false })
        );
    }
}
