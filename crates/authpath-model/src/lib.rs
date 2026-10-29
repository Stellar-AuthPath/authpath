//! Validated, non-secret Stellar account configuration data.
//!
//! This crate deliberately stops at the account snapshot boundary. It does
//! not verify signatures, hold private keys, evaluate transaction thresholds,
//! read ledgers, or submit transactions.

#![forbid(unsafe_code)]

use std::{collections::BTreeSet, fmt, str::FromStr};

use stellar_strkey::ed25519::PublicKey;

/// The maximum number of additional signers allowed on a Stellar account.
pub const MAX_SIGNERS: usize = 20;

/// A canonical Stellar account identity encoded as a G... Ed25519 strkey.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountId(PublicKey);

impl AccountId {
    /// Constructs an account identity from its 32-byte Ed25519 public key.
    ///
    /// The bytes are formatted as a canonical Stellar account strkey when
    /// displayed. This constructor is intended for typed inputs and
    /// deterministic fixtures; it does not fetch or prove ledger existence.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(PublicKey(bytes))
    }

    /// Returns the raw Ed25519 public-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0.0
    }

    /// Returns this account identity as a canonical Stellar strkey.
    #[must_use]
    pub fn to_strkey(&self) -> String {
        format!("{}", self.0)
    }

    /// Views the account identity as an Ed25519 public signer key.
    #[must_use]
    pub const fn as_ed25519_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.0)
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_strkey())
    }
}

impl FromStr for AccountId {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        PublicKey::from_str(value)
            .map(Self)
            .map_err(|_| ModelError::MalformedAccountId)
    }
}

/// An Ed25519 public key used as an additional Stellar signer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ed25519PublicKey(PublicKey);

impl Ed25519PublicKey {
    /// Constructs a signer key from its 32-byte Ed25519 public key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(PublicKey(bytes))
    }

    /// Returns the raw Ed25519 public-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0.0
    }

    /// Returns this signer key as a canonical G... Stellar strkey.
    #[must_use]
    pub fn to_strkey(&self) -> String {
        format!("{}", self.0)
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_strkey())
    }
}

impl FromStr for Ed25519PublicKey {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        PublicKey::from_str(value)
            .map(Self)
            .map_err(|_| ModelError::MalformedEd25519SignerKey)
    }
}

/// The field whose one-byte protocol-domain validation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WeightField {
    /// The account's master-key weight.
    MasterKeyWeight,
    /// An additional signer's weight.
    SignerWeight,
    /// The low threshold.
    LowThreshold,
    /// The medium threshold.
    MediumThreshold,
    /// The high threshold.
    HighThreshold,
}

impl fmt::Display for WeightField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::MasterKeyWeight => "master-key weight",
            Self::SignerWeight => "signer weight",
            Self::LowThreshold => "low threshold",
            Self::MediumThreshold => "medium threshold",
            Self::HighThreshold => "high threshold",
        };
        formatter.write_str(name)
    }
}

/// Stellar signer kinds understood by the snapshot input boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SignerType {
    /// An Ed25519 public-key signer.
    Ed25519,
    /// A pre-authorized transaction hash signer.
    PreAuthTx,
    /// A hash-X signer.
    HashX,
    /// An Ed25519 signed-payload signer.
    Ed25519SignedPayload,
    /// A signer type not known to this version of the model.
    Unknown(u32),
}

impl fmt::Display for SignerType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 => formatter.write_str("Ed25519"),
            Self::PreAuthTx => formatter.write_str("pre-authorized transaction"),
            Self::HashX => formatter.write_str("hash-X"),
            Self::Ed25519SignedPayload => formatter.write_str("Ed25519 signed payload"),
            Self::Unknown(value) => write!(formatter, "unknown ({value})"),
        }
    }
}

/// Errors returned when account configuration data cannot be represented
/// safely by the C1 model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelError {
    /// The account identifier is not a valid Ed25519 account strkey.
    MalformedAccountId,
    /// An additional signer key is not a valid Ed25519 account strkey.
    MalformedEd25519SignerKey,
    /// A weight or threshold is outside the model's 0–255 domain.
    WeightOutOfRange { field: WeightField, value: u32 },
    /// A signer key occurs more than once in a snapshot.
    DuplicateSigner { key: Ed25519PublicKey },
    /// The account master key cannot also appear as an additional signer.
    SignerIsAccountMasterKey { key: Ed25519PublicKey },
    /// The snapshot contains a signer kind not supported by this phase.
    UnsupportedSignerType { signer_type: SignerType },
    /// The snapshot exceeds the Stellar additional-signer limit.
    TooManySigners { max: usize, actual: usize },
    /// A network passphrase was empty or only whitespace.
    InvalidNetworkIdentity,
    /// A ledger-backed snapshot did not identify a positive ledger sequence.
    InvalidLedgerSequence,
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedAccountId => formatter.write_str("malformed Stellar account id"),
            Self::MalformedEd25519SignerKey => formatter.write_str("malformed Ed25519 signer key"),
            Self::WeightOutOfRange { field, value } => {
                write!(formatter, "{field} {value} is outside the 0..=255 domain")
            }
            Self::DuplicateSigner { key } => write!(formatter, "duplicate signer {key}"),
            Self::SignerIsAccountMasterKey { key } => {
                write!(formatter, "signer {key} is the account master key")
            }
            Self::UnsupportedSignerType { signer_type } => {
                write!(formatter, "unsupported signer type {signer_type}")
            }
            Self::TooManySigners { max, actual } => {
                write!(
                    formatter,
                    "snapshot contains {actual} signers; maximum is {max}"
                )
            }
            Self::InvalidNetworkIdentity => {
                formatter.write_str("network identity must contain a non-whitespace passphrase")
            }
            Self::InvalidLedgerSequence => {
                formatter.write_str("ledger sequence must be greater than zero")
            }
        }
    }
}

impl std::error::Error for ModelError {}

fn parse_byte(value: u32, field: WeightField) -> Result<u8, ModelError> {
    u8::try_from(value).map_err(|_| ModelError::WeightOutOfRange { field, value })
}

/// The configured weight of an account's master Ed25519 key.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MasterKeyWeight(u8);

impl MasterKeyWeight {
    /// Validates and constructs a master-key weight.
    pub fn new(value: u32) -> Result<Self, ModelError> {
        Ok(Self(parse_byte(value, WeightField::MasterKeyWeight)?))
    }

    /// Constructs a master-key weight from an already bounded byte.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        Self(value)
    }

    /// Returns the configured weight.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl TryFrom<u32> for MasterKeyWeight {
    type Error = ModelError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// The configured weight of an additional signer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SignerWeight(u8);

impl SignerWeight {
    /// Validates and constructs a signer weight.
    pub fn new(value: u32) -> Result<Self, ModelError> {
        Ok(Self(parse_byte(value, WeightField::SignerWeight)?))
    }

    /// Constructs a signer weight from an already bounded byte.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        Self(value)
    }

    /// Returns the configured weight.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl TryFrom<u32> for SignerWeight {
    type Error = ModelError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A one-byte threshold value.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Threshold(u8);

impl Threshold {
    /// Constructs a threshold from an already bounded byte.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        Self(value)
    }

    /// Returns the threshold value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// The low, medium, and high thresholds for an account configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Thresholds {
    low: Threshold,
    medium: Threshold,
    high: Threshold,
}

impl Thresholds {
    /// Validates and constructs the three account thresholds.
    ///
    /// Thresholds are independent protocol values; C1 does not impose an
    /// ordering relationship between low, medium, and high thresholds.
    pub fn new(low: u32, medium: u32, high: u32) -> Result<Self, ModelError> {
        Ok(Self {
            low: Threshold(parse_byte(low, WeightField::LowThreshold)?),
            medium: Threshold(parse_byte(medium, WeightField::MediumThreshold)?),
            high: Threshold(parse_byte(high, WeightField::HighThreshold)?),
        })
    }

    /// Returns the low threshold.
    #[must_use]
    pub const fn low(self) -> Threshold {
        self.low
    }

    /// Returns the medium threshold.
    #[must_use]
    pub const fn medium(self) -> Threshold {
        self.medium
    }

    /// Returns the high threshold.
    #[must_use]
    pub const fn high(self) -> Threshold {
        self.high
    }
}

/// An explicit declaration about whether a configured signer's private key
/// is available to the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerAvailability {
    /// The caller explicitly declares the corresponding private key available.
    Available,
    /// The caller explicitly declares the corresponding private key unavailable.
    Unavailable,
}

/// An Ed25519 signer configured on an account, with independent availability
/// metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredSigner {
    key: Ed25519PublicKey,
    weight: SignerWeight,
    availability: SignerAvailability,
}

impl ConfiguredSigner {
    /// Constructs a configured signer. No private-key material is accepted.
    #[must_use]
    pub const fn new(
        key: Ed25519PublicKey,
        weight: SignerWeight,
        availability: SignerAvailability,
    ) -> Self {
        Self {
            key,
            weight,
            availability,
        }
    }

    /// Returns the signer's public key.
    #[must_use]
    pub const fn key(&self) -> &Ed25519PublicKey {
        &self.key
    }

    /// Returns the signer's configured weight.
    #[must_use]
    pub const fn weight(&self) -> SignerWeight {
        self.weight
    }

    /// Returns the explicit key-availability declaration.
    #[must_use]
    pub const fn availability(&self) -> SignerAvailability {
        self.availability
    }

    /// Reports whether the caller explicitly declared the key available.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self.availability, SignerAvailability::Available)
    }
}

/// A signer supplied at the untrusted snapshot conversion boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RawSigner {
    /// A textual Ed25519 signer with a numeric weight and explicit availability.
    Ed25519 {
        key: String,
        weight: u32,
        availability: SignerAvailability,
    },
    /// A signer kind that C1 must reject rather than coerce.
    Unsupported {
        signer_type: SignerType,
        weight: u32,
    },
}

impl RawSigner {
    /// Creates a raw Ed25519 signer entry.
    pub fn ed25519(key: impl Into<String>, weight: u32, availability: SignerAvailability) -> Self {
        Self::Ed25519 {
            key: key.into(),
            weight,
            availability,
        }
    }

    /// Creates a raw unsupported signer entry for rejection testing or adapters.
    #[must_use]
    pub const fn unsupported(signer_type: SignerType, weight: u32) -> Self {
        Self::Unsupported {
            signer_type,
            weight,
        }
    }
}

impl TryFrom<RawSigner> for ConfiguredSigner {
    type Error = ModelError;

    fn try_from(value: RawSigner) -> Result<Self, Self::Error> {
        match value {
            RawSigner::Ed25519 {
                key,
                weight,
                availability,
            } => Ok(Self::new(
                Ed25519PublicKey::from_str(&key)?,
                SignerWeight::try_from(weight)?,
                availability,
            )),
            RawSigner::Unsupported { signer_type, .. } => {
                Err(ModelError::UnsupportedSignerType { signer_type })
            }
        }
    }
}

/// A non-empty Stellar network passphrase identifying a network context.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkIdentity(String);

impl NetworkIdentity {
    /// Validates and constructs a network identity from its passphrase.
    pub fn new(passphrase: impl Into<String>) -> Result<Self, ModelError> {
        let passphrase = passphrase.into();
        if passphrase.trim().is_empty() {
            return Err(ModelError::InvalidNetworkIdentity);
        }
        Ok(Self(passphrase))
    }

    /// Returns the network passphrase.
    #[must_use]
    pub fn passphrase(&self) -> &str {
        &self.0
    }
}

/// The declared source and network context for an account snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotProvenance {
    /// Data was supplied by a caller rather than read from a ledger.
    CallerProvided {
        /// An optional network context supplied by the caller.
        network: Option<NetworkIdentity>,
    },
    /// Data was read from a ledger-backed source.
    Ledger {
        /// The network on which the ledger sequence exists.
        network: NetworkIdentity,
        /// The positive ledger sequence containing the snapshot.
        ledger_sequence: u32,
    },
}

impl SnapshotProvenance {
    /// Creates caller-provided provenance.
    #[must_use]
    pub const fn caller_provided(network: Option<NetworkIdentity>) -> Self {
        Self::CallerProvided { network }
    }

    /// Creates ledger-backed provenance and validates the ledger sequence.
    pub fn ledger(network: NetworkIdentity, ledger_sequence: u32) -> Result<Self, ModelError> {
        let provenance = Self::Ledger {
            network,
            ledger_sequence,
        };
        provenance.validate()?;
        Ok(provenance)
    }

    /// Returns the declared network context, if one exists.
    #[must_use]
    pub const fn network(&self) -> Option<&NetworkIdentity> {
        match self {
            Self::CallerProvided { network } => network.as_ref(),
            Self::Ledger { network, .. } => Some(network),
        }
    }

    /// Returns the ledger sequence for ledger-backed provenance.
    #[must_use]
    pub const fn ledger_sequence(&self) -> Option<u32> {
        match self {
            Self::CallerProvided { .. } => None,
            Self::Ledger {
                ledger_sequence, ..
            } => Some(*ledger_sequence),
        }
    }

    fn validate(&self) -> Result<(), ModelError> {
        if matches!(
            self,
            Self::Ledger {
                ledger_sequence: 0,
                ..
            }
        ) {
            return Err(ModelError::InvalidLedgerSequence);
        }
        Ok(())
    }
}

/// A typed account configuration snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountSnapshot {
    account_id: AccountId,
    master_key_weight: MasterKeyWeight,
    thresholds: Thresholds,
    signers: Vec<ConfiguredSigner>,
    provenance: SnapshotProvenance,
}

impl AccountSnapshot {
    /// Validates and constructs an account configuration snapshot.
    pub fn new(
        account_id: AccountId,
        master_key_weight: MasterKeyWeight,
        thresholds: Thresholds,
        signers: Vec<ConfiguredSigner>,
        provenance: SnapshotProvenance,
    ) -> Result<Self, ModelError> {
        provenance.validate()?;

        if signers.len() > MAX_SIGNERS {
            return Err(ModelError::TooManySigners {
                max: MAX_SIGNERS,
                actual: signers.len(),
            });
        }

        let mut seen = BTreeSet::new();
        for signer in &signers {
            if account_id.as_ed25519_key() == *signer.key() {
                return Err(ModelError::SignerIsAccountMasterKey { key: *signer.key() });
            }
            if !seen.insert(*signer.key()) {
                return Err(ModelError::DuplicateSigner { key: *signer.key() });
            }
        }

        Ok(Self {
            account_id,
            master_key_weight,
            thresholds,
            signers,
            provenance,
        })
    }

    /// Returns the account identity.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the configured master-key weight.
    #[must_use]
    pub const fn master_key_weight(&self) -> MasterKeyWeight {
        self.master_key_weight
    }

    /// Returns the configured thresholds.
    #[must_use]
    pub const fn thresholds(&self) -> Thresholds {
        self.thresholds
    }

    /// Returns all configured Ed25519 signers, including zero-weight and
    /// explicitly unavailable entries.
    #[must_use]
    pub fn signers(&self) -> &[ConfiguredSigner] {
        &self.signers
    }

    /// Returns the snapshot provenance.
    #[must_use]
    pub const fn provenance(&self) -> &SnapshotProvenance {
        &self.provenance
    }

    /// Finds a configured signer by public key.
    #[must_use]
    pub fn signer(&self, key: &Ed25519PublicKey) -> Option<&ConfiguredSigner> {
        self.signers.iter().find(|signer| signer.key() == key)
    }

    /// Reports whether a configured signer was explicitly declared available.
    ///
    /// A false result does not distinguish an unknown key from an explicitly
    /// unavailable configured signer; use the signer method when that
    /// distinction matters.
    #[must_use]
    pub fn has_available_signer(&self, key: &Ed25519PublicKey) -> bool {
        self.signer(key).is_some_and(ConfiguredSigner::is_available)
    }
}

/// An account snapshot at an untrusted, textual/numeric input boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawAccountSnapshot {
    /// The account's textual G... identity.
    pub account_id: String,
    /// The account master-key weight.
    pub master_key_weight: u32,
    /// The low threshold.
    pub low_threshold: u32,
    /// The medium threshold.
    pub medium_threshold: u32,
    /// The high threshold.
    pub high_threshold: u32,
    /// The account's raw signer entries.
    pub signers: Vec<RawSigner>,
    /// The caller-declared snapshot provenance.
    pub provenance: SnapshotProvenance,
}

impl RawAccountSnapshot {
    /// Creates a raw account snapshot for conversion into validated types.
    #[must_use]
    pub fn new(
        account_id: impl Into<String>,
        master_key_weight: u32,
        low_threshold: u32,
        medium_threshold: u32,
        high_threshold: u32,
        signers: Vec<RawSigner>,
        provenance: SnapshotProvenance,
    ) -> Self {
        Self {
            account_id: account_id.into(),
            master_key_weight,
            low_threshold,
            medium_threshold,
            high_threshold,
            signers,
            provenance,
        }
    }
}

impl TryFrom<RawAccountSnapshot> for AccountSnapshot {
    type Error = ModelError;

    fn try_from(value: RawAccountSnapshot) -> Result<Self, Self::Error> {
        let RawAccountSnapshot {
            account_id,
            master_key_weight,
            low_threshold,
            medium_threshold,
            high_threshold,
            signers,
            provenance,
        } = value;

        let account_id = AccountId::from_str(&account_id)?;
        let master_key_weight = MasterKeyWeight::try_from(master_key_weight)?;
        let thresholds = Thresholds::new(low_threshold, medium_threshold, high_threshold)?;
        let signers = signers
            .into_iter()
            .map(ConfiguredSigner::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Self::new(
            account_id,
            master_key_weight,
            thresholds,
            signers,
            provenance,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(seed: u8) -> AccountId {
        AccountId::from_bytes([seed; 32])
    }

    fn signer(seed: u8) -> Ed25519PublicKey {
        Ed25519PublicKey::from_bytes([seed; 32])
    }

    fn availability() -> SnapshotProvenance {
        SnapshotProvenance::caller_provided(None)
    }

    fn configured(seed: u8, weight: u32, state: SignerAvailability) -> ConfiguredSigner {
        ConfiguredSigner::new(signer(seed), SignerWeight::new(weight).unwrap(), state)
    }

    fn valid_snapshot() -> AccountSnapshot {
        AccountSnapshot::new(
            account(1),
            MasterKeyWeight::new(1).unwrap(),
            Thresholds::new(0, 2, 3).unwrap(),
            vec![configured(2, 3, SignerAvailability::Available)],
            availability(),
        )
        .unwrap()
    }

    #[test]
    fn accepts_a_valid_configuration() {
        let snapshot = valid_snapshot();

        assert_eq!(snapshot.account_id(), &account(1));
        assert_eq!(snapshot.master_key_weight().value(), 1);
        assert_eq!(snapshot.thresholds().low().value(), 0);
        assert_eq!(snapshot.thresholds().medium().value(), 2);
        assert_eq!(snapshot.thresholds().high().value(), 3);
        assert_eq!(snapshot.signers().len(), 1);
        assert!(snapshot.has_available_signer(&signer(2)));
    }

    #[test]
    fn keeps_missing_signer_distinct_from_configuration() {
        let snapshot = AccountSnapshot::new(
            account(1),
            MasterKeyWeight::new(1).unwrap(),
            Thresholds::new(1, 1, 1).unwrap(),
            vec![configured(2, 7, SignerAvailability::Unavailable)],
            availability(),
        )
        .unwrap();

        assert_eq!(snapshot.signer(&signer(2)).unwrap().weight().value(), 7);
        assert_eq!(
            snapshot.signer(&signer(2)).unwrap().availability(),
            SignerAvailability::Unavailable
        );
        assert!(!snapshot.has_available_signer(&signer(2)));
    }

    #[test]
    fn accepts_zero_weight_signers_without_inferencing_availability() {
        let snapshot = AccountSnapshot::new(
            account(1),
            MasterKeyWeight::new(0).unwrap(),
            Thresholds::new(0, 0, 0).unwrap(),
            vec![configured(2, 0, SignerAvailability::Available)],
            availability(),
        )
        .unwrap();

        assert_eq!(snapshot.signer(&signer(2)).unwrap().weight().value(), 0);
        assert!(snapshot.has_available_signer(&signer(2)));
    }

    #[test]
    fn rejects_duplicate_signer_keys() {
        let error = AccountSnapshot::new(
            account(1),
            MasterKeyWeight::new(1).unwrap(),
            Thresholds::new(1, 1, 1).unwrap(),
            vec![
                configured(2, 1, SignerAvailability::Available),
                configured(2, 9, SignerAvailability::Unavailable),
            ],
            availability(),
        )
        .unwrap_err();

        assert!(matches!(error, ModelError::DuplicateSigner { .. }));
    }

    #[test]
    fn rejects_the_account_master_key_as_an_additional_signer() {
        let error = AccountSnapshot::new(
            account(1),
            MasterKeyWeight::new(1).unwrap(),
            Thresholds::new(1, 1, 1).unwrap(),
            vec![ConfiguredSigner::new(
                account(1).as_ed25519_key(),
                SignerWeight::new(1).unwrap(),
                SignerAvailability::Available,
            )],
            availability(),
        )
        .unwrap_err();

        assert!(matches!(error, ModelError::SignerIsAccountMasterKey { .. }));
    }

    #[test]
    fn validates_threshold_boundaries() {
        let thresholds = Thresholds::new(0, 255, 255).unwrap();
        assert_eq!(thresholds.low().value(), 0);
        assert_eq!(thresholds.medium().value(), 255);
        assert_eq!(thresholds.high().value(), 255);

        let error = Thresholds::new(256, 0, 0).unwrap_err();
        assert_eq!(
            error,
            ModelError::WeightOutOfRange {
                field: WeightField::LowThreshold,
                value: 256,
            }
        );
        assert!(MasterKeyWeight::new(256).is_err());
        assert!(SignerWeight::new(256).is_err());
    }

    #[test]
    fn rejects_unsupported_signer_types() {
        let raw = RawAccountSnapshot::new(
            account(1).to_strkey(),
            1,
            1,
            1,
            1,
            vec![RawSigner::unsupported(SignerType::HashX, 1)],
            availability(),
        );

        let error = AccountSnapshot::try_from(raw).unwrap_err();
        assert_eq!(
            error,
            ModelError::UnsupportedSignerType {
                signer_type: SignerType::HashX,
            }
        );
    }

    #[test]
    fn rejects_malformed_account_snapshot_values() {
        let malformed_account =
            RawAccountSnapshot::new("not-an-account", 1, 1, 1, 1, vec![], availability());
        assert_eq!(
            AccountSnapshot::try_from(malformed_account).unwrap_err(),
            ModelError::MalformedAccountId
        );

        let malformed_signer = RawAccountSnapshot::new(
            account(1).to_strkey(),
            1,
            1,
            1,
            1,
            vec![RawSigner::ed25519(
                "not-a-signer",
                1,
                SignerAvailability::Available,
            )],
            availability(),
        );
        assert_eq!(
            AccountSnapshot::try_from(malformed_signer).unwrap_err(),
            ModelError::MalformedEd25519SignerKey
        );

        let malformed_weight =
            RawAccountSnapshot::new(account(1).to_strkey(), 256, 1, 1, 1, vec![], availability());
        assert!(matches!(
            AccountSnapshot::try_from(malformed_weight),
            Err(ModelError::WeightOutOfRange {
                field: WeightField::MasterKeyWeight,
                value: 256
            })
        ));
    }

    #[test]
    fn validates_snapshot_provenance() {
        assert!(NetworkIdentity::new("   ").is_err());

        let network = NetworkIdentity::new("fixture-network").unwrap();
        let provenance = SnapshotProvenance::ledger(network.clone(), 42).unwrap();
        assert_eq!(
            provenance.network().unwrap().passphrase(),
            "fixture-network"
        );
        assert_eq!(provenance.ledger_sequence(), Some(42));
        assert!(SnapshotProvenance::ledger(network, 0).is_err());

        let invalid = SnapshotProvenance::Ledger {
            network: NetworkIdentity::new("fixture-network").unwrap(),
            ledger_sequence: 0,
        };
        assert!(
            AccountSnapshot::new(
                account(1),
                MasterKeyWeight::new(1).unwrap(),
                Thresholds::new(1, 1, 1).unwrap(),
                vec![],
                invalid,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_more_than_the_protocol_signer_limit() {
        let signers = (2..=22)
            .map(|seed| configured(seed, 1, SignerAvailability::Unavailable))
            .collect();

        let error = AccountSnapshot::new(
            account(1),
            MasterKeyWeight::new(1).unwrap(),
            Thresholds::new(1, 1, 1).unwrap(),
            signers,
            availability(),
        )
        .unwrap_err();

        assert_eq!(
            error,
            ModelError::TooManySigners {
                max: MAX_SIGNERS,
                actual: 21,
            }
        );
    }
}
