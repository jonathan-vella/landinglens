"""Explicit maintainer capture of reviewed control-source metadata, not runtime acquisition."""

import hashlib
import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [
    (
        "storage-guidance",
        "https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer",
        "Require secure transfer for storage REST requests; Azure Files needs separate analysis.",
        ["Secure transfer required", "HTTPS"],
        "CC-BY-4.0 documentation; metadata only",
    ),
    (
        "firewall-guidance",
        "https://learn.microsoft.com/en-us/azure/firewall/dns-settings",
        "DNS proxy is an explicit setting; policy DNS settings can override/inherit. "
        "Client DNS routing and operational effectiveness are not proved by the flag.",
        ["DNS proxy", "Policy inheritance"],
        "CC-BY-4.0 documentation; metadata only",
    ),
    (
        "storage-arm",
        "https://learn.microsoft.com/en-us/azure/templates/microsoft.storage/2023-05-01/storageaccounts",
        "2023-05-01 ARM storage-account properties.supportsHttpsTrafficOnly is a boolean.",
        ["supportsHttpsTrafficOnly"],
        "CC-BY-4.0 documentation; metadata only",
    ),
    (
        "firewall-arm",
        "https://learn.microsoft.com/en-us/azure/templates/microsoft.network/2024-05-01/firewallpolicies",
        "2024-05-01 ARM firewall-policy properties.dnsSettings.enableProxy is a boolean.",
        ["dnsSettings", "enableProxy"],
        "CC-BY-4.0 documentation; metadata only",
    ),
]


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "LandingLens-source-review/0.1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        content = response.read(8_000_001)
        if len(content) > 8_000_000:
            raise RuntimeError("Reference exceeds acquisition bound")
        return content


def main() -> None:
    destination = ROOT / "references" / "2026-11-04-controls"
    destination.mkdir(exist_ok=True)
    target = destination / "manifest.json"
    if target.exists():
        raise RuntimeError("Frozen review already exists; create a new explicitly reviewed version")
    tag = json.loads(
        fetch(
            "https://api.github.com/repos/hashicorp/terraform-provider-azurerm/commits/v4.50.0",
        )
    )
    revision = tag["sha"]
    sources = list(SOURCES)
    for kind, field in (
        ("storage_account", "https_traffic_only_enabled"),
        ("firewall_policy", "proxy_enabled"),
    ):
        sources.append(
            (
                "terraform-" + kind,
                f"https://raw.githubusercontent.com/hashicorp/terraform-provider-azurerm/{revision}/"
                f"website/docs/r/{kind}.html.markdown",
                f"AzureRM 4.50.0 explicit {field} mapping only; "
                "omitted provider defaults are not inferred.",
                [field],
                "MPL-2.0 provider documentation; metadata and own factual notes only",
            )
        )
    records = []
    for name, url, finding, markers, license_note in sources:
        content = fetch(url)
        if not all(marker.encode().lower() in content.lower() for marker in markers):
            raise RuntimeError(f"Reviewed field not found in actual source: {name}")
        records.append(
            {
                "id": name,
                "url": url,
                "sha256": hashlib.sha256(content).hexdigest(),
                "retrieved_at": datetime.now(UTC).isoformat(),
                "finding": finding,
                "revision": revision if name.startswith("terraform-") else "retrieved-page",
                "reuse": license_note,
            }
        )
    target.write_text(
        json.dumps(
            {
                "version": "2026-11-04-controls.1",
                "review_state": "reviewed-property-subsets-not-certification",
                "sources": records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
