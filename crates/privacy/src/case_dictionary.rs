//! Case-scoped dictionary, stable alias ledger, and cross-document cluster mutations.
//!
//! Public records contain only keyed fingerprints and encrypted-vault references. Decrypted terms
//! are borrowed at the call boundary and cannot be serialized or logged by these types.

use crate::{
    deterministic::{DetectionContextV1, DeterministicDetectorError, StoredPrivateValueBindingV1},
    finding_engine::FindingCandidateV1,
    sha256_hex,
    vnext::{
        canonical_json_v1, strict_json_v1_from_slice, CaseId, ClusterId, ConfidencePpm, EntityType,
        HumanOverrideV1, PrivacyFindingV1, PrivateValueRefV1, ReviewResolution, Sha256Hex,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, error::Error, fmt};

pub const CASE_DICTIONARY_SCHEMA_VERSION: &str = "case-dictionary-v1";
pub const CASE_ALIAS_LEDGER_SCHEMA_VERSION: &str = "case-alias-ledger-v1";
pub const CASE_DICTIONARY_DETECTOR_VERSION: &str = "case-dictionary-exact-v1";
pub const MAX_DICTIONARY_ENTRIES: usize = 4_096;
pub const MAX_DICTIONARY_VARIANTS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DictionaryCategoryV1 {
    Party,
    Agent,
    LegalRepresentative,
    Contact,
    Witness,
    Company,
    Agency,
    Court,
    Address,
    ContactInformation,
    Account,
    Custom,
}

impl DictionaryCategoryV1 {
    pub const fn default_entity_type(self) -> EntityType {
        match self {
            Self::Party
            | Self::Agent
            | Self::LegalRepresentative
            | Self::Contact
            | Self::Witness => EntityType::PersonName,
            Self::Company | Self::Agency | Self::Court => EntityType::OrganizationName,
            Self::Address => EntityType::Address,
            Self::ContactInformation => EntityType::PhoneNumber,
            Self::Account => EntityType::AccountName,
            Self::Custom => EntityType::Custom,
        }
    }

    const fn alias_stem(self) -> &'static str {
        match self {
            Self::Party
            | Self::Agent
            | Self::LegalRepresentative
            | Self::Contact
            | Self::Witness => "\u{81ea}\u{7136}\u{4eba}",
            Self::Company => "\u{516c}\u{53f8}",
            Self::Agency => "\u{673a}\u{5173}",
            Self::Court => "\u{6cd5}\u{9662}",
            Self::Address => "\u{5730}\u{5740}",
            Self::ContactInformation => "\u{8054}\u{7cfb}\u{65b9}\u{5f0f}",
            Self::Account => "\u{8d26}\u{53f7}",
            Self::Custom => "\u{654f}\u{611f}\u{8bcd}",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseDictionaryError {
    InvalidRecord,
    InvalidSecret,
    EntryLimitExceeded,
    PrivateValueStoreFailed,
    BindingMismatch,
    InvalidClusterOperation,
}

impl fmt::Display for CaseDictionaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRecord => "case_dictionary_record_invalid",
            Self::InvalidSecret => "case_dictionary_secret_invalid",
            Self::EntryLimitExceeded => "case_dictionary_entry_limit_exceeded",
            Self::PrivateValueStoreFailed => "case_dictionary_private_store_failed",
            Self::BindingMismatch => "case_dictionary_private_binding_mismatch",
            Self::InvalidClusterOperation => "case_dictionary_cluster_operation_invalid",
        })
    }
}

impl Error for CaseDictionaryError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CaseDictionaryRecordV1 {
    pub schema_version: String,
    pub entry_id: String,
    pub case_id: CaseId,
    pub category: DictionaryCategoryV1,
    pub entity_type: EntityType,
    pub required: bool,
    pub stable_alias: String,
    pub value_fingerprint: Sha256Hex,
    pub private_value_ref: PrivateValueRefV1,
    pub revision: u64,
}

impl CaseDictionaryRecordV1 {
    pub fn validate(&self) -> Result<(), CaseDictionaryError> {
        let valid_id = self.entry_id.strip_prefix("dict_").is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        if self.schema_version != CASE_DICTIONARY_SCHEMA_VERSION
            || !valid_id
            || self.revision == 0
            || self.private_value_ref.object_version == 0
            || !valid_alias(&self.stable_alias)
        {
            return Err(CaseDictionaryError::InvalidRecord);
        }
        Ok(())
    }
}

/// Decrypted dictionary view borrowed from a vault object. No debug/clone/serialization surface.
pub struct ResolvedCaseDictionaryTermV1<'a> {
    pub record: &'a CaseDictionaryRecordV1,
    pub primary_value: &'a str,
    pub variants: &'a [&'a str],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CaseAliasRecordV1 {
    pub value_fingerprint: Sha256Hex,
    pub category: DictionaryCategoryV1,
    pub stable_alias: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CaseAliasLedgerV1 {
    pub schema_version: String,
    pub case_id: CaseId,
    pub revision: u64,
    pub aliases: Vec<CaseAliasRecordV1>,
    pub revision_hash: Sha256Hex,
}

impl CaseAliasLedgerV1 {
    pub fn empty(case_id: CaseId) -> Result<Self, CaseDictionaryError> {
        let mut ledger = Self {
            schema_version: CASE_ALIAS_LEDGER_SCHEMA_VERSION.to_owned(),
            case_id,
            revision: 1,
            aliases: Vec::new(),
            revision_hash: parse_hash(sha256_hex(b"pending"))?,
        };
        ledger.rehash()?;
        Ok(ledger)
    }

    pub fn state_bytes(&self) -> Result<Vec<u8>, CaseDictionaryError> {
        self.validate()?;
        canonical_json_v1(self).map_err(|_| CaseDictionaryError::InvalidRecord)
    }

    pub fn from_state_bytes(bytes: &[u8]) -> Result<Self, CaseDictionaryError> {
        let ledger = strict_json_v1_from_slice::<Self>(bytes)
            .map_err(|_| CaseDictionaryError::InvalidRecord)?;
        ledger.validate()?;
        Ok(ledger)
    }
    pub fn assign(
        &mut self,
        category: DictionaryCategoryV1,
        fingerprint: Sha256Hex,
    ) -> Result<String, CaseDictionaryError> {
        if let Some(existing) = self
            .aliases
            .iter()
            .find(|entry| entry.value_fingerprint == fingerprint)
        {
            return Ok(existing.stable_alias.clone());
        }
        if self.aliases.len() >= MAX_DICTIONARY_ENTRIES {
            return Err(CaseDictionaryError::EntryLimitExceeded);
        }
        let ordinal = self
            .aliases
            .iter()
            .filter(|entry| entry.category == category)
            .count();
        let alias = format!(
            "\u{3010}{}{}\u{3011}",
            category.alias_stem(),
            alpha_ordinal(ordinal)
        );
        self.aliases.push(CaseAliasRecordV1 {
            value_fingerprint: fingerprint,
            category,
            stable_alias: alias.clone(),
        });
        self.aliases.sort_by(|left, right| {
            left.category
                .cmp(&right.category)
                .then_with(|| left.stable_alias.cmp(&right.stable_alias))
        });
        self.revision = self.revision.saturating_add(1);
        self.rehash()?;
        Ok(alias)
    }

    pub fn validate(&self) -> Result<(), CaseDictionaryError> {
        if self.schema_version != CASE_ALIAS_LEDGER_SCHEMA_VERSION
            || self.revision == 0
            || self.aliases.len() > MAX_DICTIONARY_ENTRIES
            || self
                .aliases
                .iter()
                .any(|entry| !valid_alias(&entry.stable_alias))
        {
            return Err(CaseDictionaryError::InvalidRecord);
        }
        let mut copy = self.clone();
        copy.rehash()?;
        if copy.revision_hash != self.revision_hash {
            return Err(CaseDictionaryError::InvalidRecord);
        }
        Ok(())
    }

    fn rehash(&mut self) -> Result<(), CaseDictionaryError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Claims<'a> {
            schema_version: &'a str,
            case_id: &'a CaseId,
            revision: u64,
            aliases: &'a [CaseAliasRecordV1],
        }
        let bytes = canonical_json_v1(&Claims {
            schema_version: &self.schema_version,
            case_id: &self.case_id,
            revision: self.revision,
            aliases: &self.aliases,
        })
        .map_err(|_| CaseDictionaryError::InvalidRecord)?;
        self.revision_hash = parse_hash(sha256_hex(&bytes))?;
        Ok(())
    }
}

pub fn build_dictionary_record(
    case_id: CaseId,
    category: DictionaryCategoryV1,
    required: bool,
    revision: u64,
    binding: StoredPrivateValueBindingV1,
    ledger: &mut CaseAliasLedgerV1,
) -> Result<CaseDictionaryRecordV1, CaseDictionaryError> {
    if ledger.case_id != case_id || revision == 0 {
        return Err(CaseDictionaryError::InvalidRecord);
    }
    let alias = ledger.assign(category, binding.value_fingerprint.clone())?;
    let digest = sha256_hex(
        format!(
            "case-dictionary-entry-v1\0{}\0{}",
            case_id.as_str(),
            binding.value_fingerprint.as_str()
        )
        .as_bytes(),
    );
    let record = CaseDictionaryRecordV1 {
        schema_version: CASE_DICTIONARY_SCHEMA_VERSION.to_owned(),
        entry_id: format!("dict_{}", &digest[..32]),
        case_id,
        category,
        entity_type: category.default_entity_type(),
        required,
        stable_alias: alias,
        value_fingerprint: binding.value_fingerprint,
        private_value_ref: binding.private_value_ref,
        revision,
    };
    record.validate()?;
    Ok(record)
}

pub fn match_case_dictionary(
    text: &str,
    context: DetectionContextV1<'_>,
    terms: &[ResolvedCaseDictionaryTermV1<'_>],
) -> Result<Vec<FindingCandidateV1>, CaseDictionaryError> {
    if terms.len() > MAX_DICTIONARY_ENTRIES {
        return Err(CaseDictionaryError::EntryLimitExceeded);
    }
    let mut matched = Vec::<DictionaryMatch<'_>>::new();
    for term in terms {
        term.record.validate()?;
        if &term.record.case_id != context.case_id
            || term.primary_value.trim().is_empty()
            || term.primary_value.len() > 512
            || term.variants.len() > MAX_DICTIONARY_VARIANTS
        {
            return Err(CaseDictionaryError::InvalidSecret);
        }
        let values = std::iter::once(term.primary_value).chain(term.variants.iter().copied());
        for value in values {
            if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
                return Err(CaseDictionaryError::InvalidSecret);
            }
            for (start, _) in text.match_indices(value) {
                let end = start.saturating_add(value.len());
                matched.push(DictionaryMatch { start, end, term });
            }
        }
    }
    matched.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.end.cmp(&left.end))
            .then_with(|| left.term.record.entry_id.cmp(&right.term.record.entry_id))
    });
    matched.dedup_by(|left, right| {
        left.start == right.start
            && left.end == right.end
            && left.term.record.entry_id == right.term.record.entry_id
    });

    let mut output = Vec::with_capacity(matched.len());
    for item in matched {
        let binding = StoredPrivateValueBindingV1 {
            value_fingerprint: item.term.record.value_fingerprint.clone(),
            private_value_ref: item.term.record.private_value_ref.clone(),
            proposed_replacement: item.term.record.stable_alias.clone(),
        };
        let confidence =
            ConfidencePpm::new(1_000_000).map_err(|_| CaseDictionaryError::InvalidRecord)?;
        output.push(FindingCandidateV1 {
            page_index: context.page_index,
            block_id: context.block_id.to_owned(),
            start_offset: u32::try_from(item.start)
                .map_err(|_| CaseDictionaryError::InvalidSecret)?,
            end_offset: u32::try_from(item.end).map_err(|_| CaseDictionaryError::InvalidSecret)?,
            geometry: None,
            entity_type: item.term.record.entity_type,
            detector_source: "case_dictionary".to_owned(),
            detector_version: CASE_DICTIONARY_DETECTOR_VERSION.to_owned(),
            model_versions: Default::default(),
            raw_score_ppm: Some(confidence),
            calibrated_confidence_ppm: Some(confidence),
            ocr_confidence_ppm: context.ocr_confidence_ppm,
            layout_confidence_ppm: context.layout_confidence_ppm,
            normalization_evidence_hash: Some(parse_hash(sha256_hex(
                b"dictionary-exact-normalization-v1",
            ))?),
            confusable_evidence_hash: None,
            case_dictionary_match: true,
            value_fingerprint: binding.value_fingerprint,
            proposed_replacement: Some(item.term.record.stable_alias.clone()),
            private_value_ref: binding.private_value_ref,
            validation_passed: true,
            automatic_replacement_allowed: true,
            replacement_verified: false,
        });
    }
    Ok(output)
}

struct DictionaryMatch<'a> {
    start: usize,
    end: usize,
    term: &'a ResolvedCaseDictionaryTermV1<'a>,
}

pub fn merge_cluster(
    findings: &mut [PrivacyFindingV1],
    source_clusters: &[ClusterId],
    target_cluster: ClusterId,
    actor_hash: Sha256Hex,
    resolved_at_unix: u64,
) -> Result<usize, CaseDictionaryError> {
    if source_clusters.len() < 2 || resolved_at_unix == 0 {
        return Err(CaseDictionaryError::InvalidClusterOperation);
    }
    let source = source_clusters.iter().collect::<BTreeSet<_>>();
    let mut changed = 0_usize;
    for finding in findings {
        if finding
            .cluster_id
            .as_ref()
            .is_some_and(|cluster| source.contains(cluster))
        {
            finding.cluster_id = Some(target_cluster.clone());
            finding.resolution_state = ReviewResolution::ClusterMerged;
            finding.human_override = Some(HumanOverrideV1 {
                resolution: ReviewResolution::ClusterMerged,
                reason_code: "user_confirmed_cluster_merge".to_owned(),
                actor_hash: actor_hash.clone(),
                resolved_at_unix,
            });
            finding.reason_codes.push("cluster_merged".to_owned());
            changed += 1;
        }
    }
    if changed == 0 {
        return Err(CaseDictionaryError::InvalidClusterOperation);
    }
    Ok(changed)
}

pub fn split_finding_cluster(
    finding: &mut PrivacyFindingV1,
    actor_hash: Sha256Hex,
    resolved_at_unix: u64,
) -> Result<ClusterId, CaseDictionaryError> {
    if resolved_at_unix == 0 || finding.cluster_id.is_none() {
        return Err(CaseDictionaryError::InvalidClusterOperation);
    }
    let digest = sha256_hex(
        format!(
            "cluster-split-v1\0{}\0{}\0{}",
            finding.case_id.as_str(),
            finding.finding_id.as_str(),
            resolved_at_unix
        )
        .as_bytes(),
    );
    let cluster = ClusterId::parse(format!("clu_{}", &digest[..32]))
        .map_err(|_| CaseDictionaryError::InvalidClusterOperation)?;
    finding.cluster_id = Some(cluster.clone());
    finding.resolution_state = ReviewResolution::ClusterSplit;
    finding.human_override = Some(HumanOverrideV1 {
        resolution: ReviewResolution::ClusterSplit,
        reason_code: "user_confirmed_cluster_split".to_owned(),
        actor_hash,
        resolved_at_unix,
    });
    finding.reason_codes.push("cluster_split".to_owned());
    Ok(cluster)
}

fn alpha_ordinal(mut index: usize) -> String {
    let mut output = Vec::new();
    loop {
        output.push(char::from(b'A' + u8::try_from(index % 26).unwrap_or(0)));
        if index < 26 {
            break;
        }
        index = index / 26 - 1;
    }
    output.iter().rev().collect()
}

fn valid_alias(value: &str) -> bool {
    value.starts_with('\u{3010}')
        && value.ends_with('\u{3011}')
        && value.len() <= 128
        && !value.chars().any(char::is_control)
}

fn parse_hash(value: String) -> Result<Sha256Hex, CaseDictionaryError> {
    Sha256Hex::parse(value).map_err(|_| CaseDictionaryError::InvalidRecord)
}

impl From<DeterministicDetectorError> for CaseDictionaryError {
    fn from(_: DeterministicDetectorError) -> Self {
        Self::PrivateValueStoreFailed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vnext::{MaterialId, ObjectId};

    fn binding(value: &str) -> StoredPrivateValueBindingV1 {
        let digest = sha256_hex(format!("keyed\0{value}").as_bytes());
        StoredPrivateValueBindingV1 {
            value_fingerprint: Sha256Hex::parse(digest.clone()).expect("fingerprint"),
            private_value_ref: PrivateValueRefV1 {
                object_id: ObjectId::parse(format!("obj_{}", &digest[..32])).expect("object"),
                object_version: 1,
                value_locator_hash: Sha256Hex::parse(sha256_hex(
                    format!("loc\0{value}").as_bytes(),
                ))
                .expect("locator"),
            },
            proposed_replacement: "[unused]".to_owned(),
        }
    }

    #[test]
    fn stable_alias_survives_cross_document_order() {
        let case_id = CaseId::parse("case_11111111111111111111111111111111").expect("case");
        let first = binding("subject-one");
        let second = binding("subject-two");
        let mut ledger = CaseAliasLedgerV1::empty(case_id.clone()).expect("ledger");
        let one = build_dictionary_record(
            case_id.clone(),
            DictionaryCategoryV1::Party,
            true,
            1,
            first,
            &mut ledger,
        )
        .expect("one");
        let two = build_dictionary_record(
            case_id,
            DictionaryCategoryV1::Party,
            true,
            1,
            second,
            &mut ledger,
        )
        .expect("two");
        assert_eq!(
            one.stable_alias,
            "\u{3010}\u{81ea}\u{7136}\u{4eba}A\u{3011}"
        );
        assert_eq!(
            two.stable_alias,
            "\u{3010}\u{81ea}\u{7136}\u{4eba}B\u{3011}"
        );
        ledger.validate().expect("valid ledger");
        let state = ledger.state_bytes().expect("ledger state");
        let restored = CaseAliasLedgerV1::from_state_bytes(&state).expect("restore ledger");
        assert_eq!(restored, ledger);
        let mut tampered: serde_json::Value = serde_json::from_slice(&state).expect("json");
        tampered["aliases"][0]["stableAlias"] = serde_json::json!("[CHANGED]");
        assert_eq!(
            CaseAliasLedgerV1::from_state_bytes(
                &serde_json::to_vec(&tampered).expect("tampered ledger")
            ),
            Err(CaseDictionaryError::InvalidRecord)
        );
        let wire = serde_json::to_string(&ledger).expect("wire");
        assert!(!wire.contains("subject-one"));
        assert!(!wire.contains("subject-two"));
    }

    #[test]
    fn exact_dictionary_match_uses_real_record_binding_and_alias() {
        let case_id = CaseId::parse("case_11111111111111111111111111111111").expect("case");
        let material_id =
            MaterialId::parse("mat_22222222222222222222222222222222").expect("material");
        let private = binding("subject-one");
        let mut ledger = CaseAliasLedgerV1::empty(case_id.clone()).expect("ledger");
        let record = build_dictionary_record(
            case_id.clone(),
            DictionaryCategoryV1::Party,
            true,
            1,
            private.clone(),
            &mut ledger,
        )
        .expect("record");
        let term = ResolvedCaseDictionaryTermV1 {
            record: &record,
            primary_value: "subject-one",
            variants: &["subject-1"],
        };
        let context = DetectionContextV1 {
            case_id: &case_id,
            material_id: &material_id,
            document_version: 1,
            page_index: 0,
            block_id: "page-1",
            ocr_confidence_ppm: None,
            layout_confidence_ppm: None,
        };
        let findings =
            match_case_dictionary("subject-one and subject-1", context, &[term]).expect("match");
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|finding| finding.case_dictionary_match));
        assert!(findings
            .iter()
            .all(|finding| finding.proposed_replacement.as_deref()
                == Some("\u{3010}\u{81ea}\u{7136}\u{4eba}A\u{3011}")));
    }
}
