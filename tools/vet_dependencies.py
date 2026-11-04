"""Capture metadata and feed availability for the exact development dependency set."""

import hashlib
import json
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

PINS = {
    "python-hcl2": "8.1.4",
    "lark": "1.3.1",
    "regex": "2026.9.29",
    "ruff": "0.17.3",
    "mypy": "1.18.2",
    "mypy-extensions": "1.1.0",
    "typing-extensions": "4.16.0",
    "pathspec": "0.12.1",
    "setuptools": "80.9.0",
}
LICENSES = {
    "python-hcl2": "MIT",
    "lark": "MIT",
    "regex": "Apache-2.0 AND CNRI-Python",
    "ruff": "MIT",
    "mypy": "MIT",
    "mypy-extensions": "MIT",
    "typing-extensions": "PSF-2.0",
    "pathspec": "MPL-2.0",
    "setuptools": "MIT",
}
REPOSITORIES = {
    "python-hcl2": "amplify-education/python-hcl2",
    "lark": "lark-parser/lark",
    "regex": "mrabarnett/mrab-regex",
    "ruff": "astral-sh/ruff",
    "mypy": "python/mypy",
    "mypy-extensions": "python/mypy_extensions",
    "typing-extensions": "python/typing_extensions",
    "pathspec": "cpburnz/python-pathspec",
    "setuptools": "pypa/setuptools",
}


def main() -> None:
    reviewed = datetime.now(UTC)
    entries = []
    for name, version in PINS.items():
        url = f"https://pypi.org/pypi/{name}/{version}/json"
        with urllib.request.urlopen(url, timeout=60) as response:
            raw = response.read()
        data = json.loads(raw)
        feed_url = f"https://packagefeedproxy.microsoft.io/pypi/simple/{name}/"
        with urllib.request.urlopen(feed_url, timeout=60) as response:
            feed = response.read()
        maintenance_url = f"https://api.github.com/repos/{REPOSITORIES[name]}"
        with urllib.request.urlopen(maintenance_url, timeout=60) as response:
            maintenance_bytes = response.read()
        maintenance = json.loads(maintenance_bytes)
        files = data["urls"]
        newest = max(datetime.fromisoformat(f["upload_time_iso_8601"]) for f in files)
        available = version.encode() in feed or version.replace("-", "_").encode() in feed
        eligible = (
            newest <= reviewed - timedelta(days=7)
            and available
            and not maintenance["archived"]
            and not maintenance["disabled"]
        )
        entries.append(
            {
                "name": name,
                "version": version,
                "metadata_url": url,
                "metadata_sha256": hashlib.sha256(raw).hexdigest(),
                "reviewed_at": reviewed.isoformat(),
                "requires_python": data["info"]["requires_python"],
                "requires_dist": data["info"]["requires_dist"],
                "license": LICENSES[name],
                "project_urls": data["info"]["project_urls"],
                "newest_artifact_upload": newest.isoformat(),
                "minimum_age_days": 7,
                "feed_url": feed_url,
                "feed_contains_version": available,
                "feed_sha256": hashlib.sha256(feed).hexdigest(),
                "maintenance_url": maintenance_url,
                "maintenance_metadata_sha256": hashlib.sha256(maintenance_bytes).hexdigest(),
                "upstream_archived": maintenance["archived"],
                "upstream_disabled": maintenance["disabled"],
                "upstream_pushed_at": maintenance["pushed_at"],
                "decision": "accepted-for-spike" if eligible else "rejected",
                "artifacts": [
                    {"filename": f["filename"], "sha256": f["digests"]["sha256"]} for f in files
                ],
            }
        )
    target = Path(__file__).resolve().parents[1] / "docs" / "dependencies.json"
    target.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    if any(entry["decision"] == "rejected" for entry in entries):
        raise SystemExit(
            "Dependency vetting failed; inspect docs/dependencies.json before installing."
        )


if __name__ == "__main__":
    main()
