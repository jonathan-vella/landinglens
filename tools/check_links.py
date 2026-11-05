"""Check local Markdown links/anchors, optionally inspect allowlisted public link status."""

import argparse
import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from alz_assessor.azure import NoRedirect

PUBLIC_HOSTS = {
    "github.com",
    "raw.githubusercontent.com",
    "learn.microsoft.com",
    "docs.github.com",
    "azure.github.io",
    "developer.hashicorp.com",
    "www.hashicorp.com",
}


def content_without_fences(text: str) -> str:
    lines = []
    fence = None
    for line in text.splitlines():
        marker = line.strip()[:3]
        if marker in {"```", "~~~"}:
            fence = None if fence == marker else marker
            continue
        if fence is None:
            lines.append(line)
    return "\n".join(lines)


def anchors(path: Path) -> set[str]:
    result = set()
    duplicates: dict[str, int] = {}
    text = content_without_fences(path.read_text("utf-8"))
    for line in text.splitlines():
        if line.startswith("#"):
            heading = line.lstrip("#").strip().rstrip("#").strip().lower()
            slug = re.sub(r"\s", "-", re.sub(r"[^\w\s-]", "", heading))
            count = duplicates.get(slug, 0)
            duplicates[slug] = count + 1
            result.add(slug + (f"-{count}" if count else ""))
    result.update(re.findall(r'\bid="([^"]+)"', text))
    return result


def public_status(url: str) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc not in PUBLIC_HOSTS or parsed.username:
        return {
            "url": url,
            "status": "not-checked",
            "reason": "Not an allowlisted public documentation host",
        }
    request = urllib.request.Request(
        url, method="HEAD", headers={"User-Agent": "LandingLens-link-check/0.1"}
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            return {"url": url, "status": response.status}
    except urllib.error.HTTPError as error:
        return {"url": url, "status": error.code, "reason": "Remote HTTP status"}
    except (OSError, ValueError):
        return {
            "url": url,
            "status": "unavailable",
            "reason": "Network/TLS status could not be verified",
        }


def check(root: Path, paths: list[Path], *, external: bool = False) -> dict[str, Any]:
    root = root.resolve()
    broken = []
    public = set()
    checked = 0
    for path in paths:
        text = content_without_fences(path.read_text("utf-8"))
        for value in re.findall(r"\]\(([^)]+)\)", text):
            checked += 1
            if urlsplit(value).scheme:
                public.add(value)
                continue
            filename, _, fragment = value.partition("#")
            target = (path.parent / unquote(filename)).resolve() if filename else path.resolve()
            if not target.is_relative_to(root) or not target.is_file():
                broken.append(
                    {
                        "file": str(path.relative_to(root)),
                        "link": value,
                        "reason": "Missing/outside repository",
                    }
                )
            elif (
                fragment
                and target.suffix.lower() == ".md"
                and unquote(fragment) not in anchors(target)
            ):
                broken.append(
                    {
                        "file": str(path.relative_to(root)),
                        "link": value,
                        "reason": "Missing local heading/anchor",
                    }
                )
    statuses = []
    if external:
        with ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(public_status, sorted(public)))
        broken.extend(item for item in statuses if item["status"] in {404, 410})
    return {
        "links_checked": checked,
        "broken": broken,
        "external": statuses,
        "warning": "403/429/unavailable/unapproved-host/redirect statuses are unverified, "
        "not fabricated successful links.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--external", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    paths = args.paths or [root / "README.md", *sorted((root / "docs").rglob("*.md"))]
    result = check(root, [path.resolve() for path in paths], external=args.external)
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)
    raise SystemExit(2 if result["broken"] else 0)
