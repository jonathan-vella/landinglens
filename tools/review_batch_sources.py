"""Explicit maintainer capture of batch-01 sources already inspected for intent and semantics."""

import argparse
import hashlib
import json
import re
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROVIDER = "211156b6c9c3c4721a2a4631998a6bd08433a9ee"
LEARN = "https://learn.microsoft.com/en-us/"
RAW = f"https://raw.githubusercontent.com/hashicorp/terraform-provider-azurerm/{PROVIDER}/"
SOURCES = [
    (
        "vault-overview",
        LEARN + "azure/key-vault/general/overview",
        ["secrets", "application"],
        "Vault storage capability and application integration are distinct; "
        "existence is not adoption.",
    ),
    (
        "vault-throttling",
        LEARN + "azure/key-vault/general/overview-throttling",
        ["throttling", "regions"],
        "Vault partitioning depends on application security/availability "
        "domains and transaction demand.",
    ),
    (
        "vault-security",
        LEARN + "azure/key-vault/general/best-practices",
        ["soft delete", "purge protection", "Privileged Identity Management", "Private Endpoints"],
        "The linked page redirects to secure-key-vault. Separately enable soft delete "
        "and purge protection; PIM, access boundaries, network alternatives and audit "
        "integration require distinct evidence.",
    ),
    (
        "vault-monitor",
        LEARN + "azure/key-vault/general/monitor-key-vault",
        ["diagnostic setting", "Resource Logs"],
        "Resource logs require diagnostic routing; automatic metrics do not prove "
        "audit logging or a central destination.",
    ),
    (
        "vault-arm",
        LEARN + "azure/templates/microsoft.keyvault/2024-11-01/vaults",
        ["enableSoftDelete", "enablePurgeProtection"],
        "2024-11-01 exposes two separate boolean properties. Omitted documented "
        "creation defaults are not inferred.",
    ),
    (
        "vault-rest",
        LEARN + "rest/api/keyvault/keyvault/vaults/get?view=rest-keyvault-keyvault-2024-11-01",
        ["2024-11-01", "enableSoftDelete", "enablePurgeProtection"],
        "Scoped ARM GET retrieves one vault. The initially attempted 2023-07-01 "
        "Learn REST view falls back to 2024-11-01; only the actually reviewed "
        "2024-11-01 API is accepted.",
    ),
    (
        "container-guidance",
        LEARN + "azure/storage/blobs/soft-delete-container-overview",
        ["container", "365"],
        "Container protection differs from blob and account deletion protection. "
        "The supported retention range is 1-365; adequacy is workload-specific.",
    ),
    (
        "storage-data-protection",
        LEARN + "azure/storage/blobs/data-protection-overview",
        ["container soft delete", "basic data protection"],
        "Actual checklist-linked overview recommends enabling container and blob "
        "soft delete separately. Its link on G04.03 is insufficient policy-specific "
        "mapping; supplement it with TLS policy guidance.",
    ),
    (
        "blob-arm",
        LEARN + "azure/templates/microsoft.storage/2023-05-01/storageaccounts/blobservices",
        ["containerDeleteRetentionPolicy", "enabled", "365"],
        "The explicit container retention enabled boolean belongs to the default "
        "blob-service child, not the storage-account or blob-retention flag.",
    ),
    (
        "blob-rest",
        LEARN
        + "rest/api/storagerp/blob-services/get-service-properties?view=rest-storagerp-2023-05-01",
        ["2023-05-01", "containerDeleteRetentionPolicy", "blobServices/default"],
        "Scoped management.azure.com GET retrieves the exact default child. "
        "It is not a storage data-plane call and its omission of container "
        "retention remains unknown.",
    ),
    (
        "storage-tls",
        LEARN + "azure/storage/common/transport-layer-security-configure-minimum-version",
        ["minimumTlsVersion", "Azure Policy"],
        "Local minimum TLS configuration differs from definition/assignment/"
        "effect/parameter/exemption-backed policy enforcement.",
    ),
    (
        "storage-arm",
        LEARN + "azure/templates/microsoft.storage/2023-05-01/storageaccounts",
        ["minimumTlsVersion", "TLS1_0", "TLS1_1", "TLS1_2"],
        "2023-05-01 declares minimum TLS enum values, including TLS1_3 while its "
        "description says 1.3 minimum is unsupported. Only explicit TLS1_0/1/2 "
        "are projected; TLS1_3 stays unknown. Local TLS is not policy enforcement.",
    ),
    (
        "terraform-vault",
        RAW + "website/docs/r/key_vault.html.markdown",
        ["purge_protection_enabled", "soft_delete_retention_days"],
        "AzureRM 4.50.0 exposes purge protection and retention days but no "
        "independent soft-delete enabled attribute.",
    ),
    (
        "terraform-vault-implementation",
        RAW + "internal/services/keyvault/key_vault_resource.go",
        ["EnableSoftDelete: pointer.To(true)", "resourceKeyVaultCreate"],
        "The provider explicitly sets soft delete during creation. That creation-only "
        "fact does not prove imported/updated vault configuration from raw or planned values.",
    ),
    (
        "terraform-storage",
        RAW + "website/docs/r/storage_account.html.markdown",
        ["container_delete_retention_policy", "365"],
        "An explicit single container retention block with valid explicit days "
        "configures container retention; omitted default days are not inferred.",
    ),
    (
        "terraform-storage-implementation",
        RAW + "internal/services/storage/storage_account_resource.go",
        ["container_delete_retention_policy", "ContainerDeleteRetentionPolicy"],
        "Provider expandAccountBlobContainerDeleteRetentionPolicy at lines 2962-2975 "
        "sets Enabled=true and Days for a present block. Only explicit valid "
        "days are projected; omitted defaults are not inferred.",
    ),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--append-new-sources", action="store_true")
    args = parser.parse_args()
    target = ROOT / "references" / "recommendation-batches" / "batch-01-sources.json"
    if target.exists() and not args.append_new_sources:
        raise ValueError("Frozen source review exists; do not silently recollect or redate it")
    sources = json.loads(target.read_text("utf-8"))["sources"] if target.exists() else []
    existing = {source["id"]: source for source in sources}
    for identity, url, markers, finding in SOURCES:
        if identity in existing:
            if existing[identity]["url"] != url:
                raise ValueError("A captured source URL changed; use a new reviewed identity")
            continue
        request = urllib.request.Request(
            url, headers={"User-Agent": "LandingLens-source-review/0.1"}
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            content = response.read(8_000_001)
            resolved = response.url
        if len(content) > 8_000_000:
            raise ValueError("Source acquisition bound exceeded")
        text = content.decode("utf-8")
        if any(marker.lower() not in text.lower() for marker in markers):
            raise ValueError(f"Reviewed marker missing from {identity}; inspect actual source")
        match = re.search(r'<meta name="git_commit_id" content="([^"]+)"', text)
        sources.append(
            {
                "id": identity,
                "url": url,
                "resolved_url": resolved,
                "sha256": hashlib.sha256(content).hexdigest(),
                "retrieved_at": datetime.now(UTC).isoformat(),
                "revision": PROVIDER
                if url.startswith(RAW)
                else match.group(1)
                if match
                else "retrieved-page",
                "finding": finding,
                "reuse": "MPL-2.0 provider: metadata and own factual findings only"
                if url.startswith(RAW)
                else (
                    "Microsoft Learn attribution: source metadata and own factual findings only; "
                    "no page content redistributed"
                ),
            }
        )
        print(identity, sources[-1]["revision"], sources[-1]["sha256"])
    target.write_text(
        json.dumps({"batch": "01", "review_state": "reviewed", "sources": sources}, indent=2)
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
