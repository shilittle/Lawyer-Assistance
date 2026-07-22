use super::*;
use crate::privacy_manager::OcrQualificationInvalidator;

impl OcrQualificationInvalidator for ApprovedMcpWorkspace {
    fn invalidate_ocr_derived(&self, _reason_code: &'static str) -> Result<u64, &'static str> {
        // Serialize provenance classification and journal revocation with every App publication
        // operation. The workspace service itself holds an immediate database transaction, so a
        // standalone MCP process can neither race an unclassified commit nor observe a partial
        // revocation set.
        let _operation = self.operation().map_err(|error| error.code())?;
        let manifest_key = self
            .inner
            .keys
            .load_or_create(KeyRole::ApprovedManifest)
            .map_err(|error| error.code())?;
        let signer = ManifestSigningKey::from_bytes(manifest_key, KEY_VERSION)
            .map_err(|_| "approved_workspace_unavailable")?;
        let verifier = signer.verification_key();
        WorkspacePublisher::initialize(&self.inner.approved_root, signer)
            .map_err(|_| "approved_workspace_unavailable")?;
        ApprovedWorkspaceService::open(&self.inner.approved_root, verifier)
            .map_err(|_| "approved_workspace_unavailable")?
            .revoke_ocr_derived_publications(now_seconds().map_err(|error| error.code())?)
            .map_err(|error| error.code())
    }
}
