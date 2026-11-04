"""Explicit-scope read-only ARM collection with injected transport for offline tests."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .arm import API_VERSIONS, properties
from .contracts import canonical_id, digest, document, now, scope_id, timestamp, validate
from .terraform import InputError

ORIGIN = "https://management.azure.com"


class TransportError(InputError):
    """A read-only request failed before a service response was available."""


@dataclass
class Response:
    status: int
    body: dict[str, Any]
    headers: dict[str, str]


def safe_url(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != "management.azure.com"
        or parsed.fragment
        or parsed.username
        or parsed.password
        or "\\" in url
        or ".." in parsed.path.split("/")
    ):
        raise InputError("Azure requests/continuations must remain on the ARM HTTPS origin")
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class HttpTransport:
    def __init__(self, token: str) -> None:
        if not token.strip() or "\n" in token or "\r" in token:
            raise InputError("A valid existing ARM token is required; no login is attempted")
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def __call__(self, method: str, url: str) -> Response:
        safe_url(url)
        if method != "GET" and not (
            method == "POST"
            and urlsplit(url).path.endswith(
                "/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults",
            )
        ):
            raise InputError("Transport rejects non-read-only operations")
        request = urllib.request.Request(
            url,
            method=method,
            data=b"" if method == "POST" else None,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                body = response.read(8_000_001)
                if len(body) > 8_000_000:
                    raise InputError("Azure response exceeds byte limit")
                data = json.loads(body)
                if not isinstance(data, dict):
                    raise InputError("Azure response must be an object")
                return Response(response.status, data, dict(response.headers))
        except urllib.error.HTTPError as exc:
            # Service error bodies and authentication headers are not exported.
            return Response(exc.code, {}, {"Retry-After": exc.headers.get("Retry-After", "1")})
        except urllib.error.URLError as exc:
            raise TransportError(
                "Azure transport unavailable; no authentication was attempted"
            ) from exc


class Collector:
    def __init__(
        self,
        transport: Callable[[str, str], Response],
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.transport, self.sleep = transport, sleep
        self.diagnostics: list[dict[str, Any]] = []
        self.artifacts: dict[str, str] = {}
        self.facets = {
            key: True
            for key in (
                "inventory",
                "configuration",
                "relationships",
                "assignments",
                "exemptions",
                "compliance",
            )
        }

    def gap(self, facet: str, reason: str, location: str) -> None:
        self.facets[facet] = False
        self.diagnostics.append({"facet": facet, "reason": reason, "source_location": location})

    def request(self, method: str, url: str, facet: str) -> dict[str, Any] | None:
        safe_url(url)
        for attempt in range(4):
            try:
                response = self.transport(method, url)
            except TransportError:
                self.gap(facet, "transport_unavailable", url)
                return None
            if response.status == 200:
                self.artifacts[method + " " + url] = digest(response.body)
                return response.body
            if response.status in {429, 500, 502, 503, 504} and attempt < 3:
                headers = {key.lower(): value for key, value in response.headers.items()}
                raw = headers.get("retry-after", str(2**attempt))
                delay = min(float(raw), 30) if raw.isdigit() else float(2**attempt)
                self.sleep(delay)
                continue
            self.gap(facet, f"http_{response.status}", url)
            return None
        raise AssertionError("bounded retry loop must return")

    def pages(self, method: str, url: str, facet: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        origin_path = urlsplit(url).path
        seen = set()
        for _ in range(100):
            if url in seen or urlsplit(safe_url(url)).path != origin_path:
                self.gap(facet, "invalid_or_repeated_continuation", url)
                return items
            seen.add(url)
            body = self.request(method, url, facet)
            if body is None:
                return items
            values = body.get("value")
            if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
                raise InputError("Azure list response requires an object value array")
            items.extend(values)
            if len(items) > 10_000:
                self.gap(facet, "item_limit", url)
                return items[:10_000]
            link = body.get("nextLink") or body.get("@odata.nextLink")
            if not link:
                return items
            if not isinstance(link, str):
                raise InputError("Azure nextLink must be a URL")
            url = link
        self.gap(facet, "page_limit", url)
        return items

    def collect(
        self,
        *,
        subscriptions: list[str] | None = None,
        management_group: str | None = None,
        inventory_authorized: bool = False,
    ) -> dict[str, Any]:
        if bool(subscriptions) == bool(management_group):
            raise InputError("Select explicit subscriptions OR one management group")
        scopes = [scope_id("/subscriptions/" + value) for value in subscriptions or []]
        if len(set(scopes)) != len(scopes):
            raise InputError("Duplicate subscription scope")
        selected = (
            scope_id("/providers/Microsoft.Management/managementGroups/" + management_group)
            if management_group
            else None
        )
        relationships = []
        if selected:
            descendants = self.pages(
                "GET", ORIGIN + selected + "/descendants?api-version=2020-05-01", "relationships"
            )
            for entry in descendants:
                identity = scope_id(entry["id"])
                parent = entry.get("properties", {}).get("parent", {}).get("id")
                relationships.append({"id": identity, "parent": parent})
                if identity.startswith("/subscriptions/"):
                    scopes.append(identity)
        scopes = sorted(set(scopes))
        if not inventory_authorized:
            self.gap(
                "inventory",
                "authorization_coverage_not_attested",
                selected or ",".join(scopes),
            )
        resources: list[dict[str, Any]] = []
        identities = set()
        assignments: dict[str, Any] = {}
        exemptions: dict[str, Any] = {}
        compliance = []
        for scope in [*([selected] if selected else []), *scopes]:
            if scope.startswith("/subscriptions/"):
                relationships.append(
                    {"id": scope, "relationship": "explicit_or_verified_descendant"}
                )
                inventory = self.pages(
                    "GET", ORIGIN + scope + "/resources?api-version=2021-04-01", "inventory"
                )
                for entry in inventory:
                    if len(resources) >= 10_000:
                        self.gap("inventory", "resource_limit", scope)
                        break
                    identity = canonical_id(entry["id"])
                    if not identity.startswith(scope.lower() + "/"):
                        self.gap("inventory", "resource_outside_requested_scope", scope)
                        continue
                    if identity in identities:
                        self.gap("inventory", "duplicate_resource", identity)
                        continue
                    identities.add(identity)
                    kind = entry.get("type")
                    if not isinstance(kind, str):
                        raise InputError("Azure resource type missing")
                    values, state, reason, version = {}, "known", "", None
                    supported = API_VERSIONS.get(kind.lower())
                    if supported:
                        version = sorted(supported)[0]
                        detail_url = ORIGIN + entry["id"] + "?api-version=" + version
                        detail = self.request("GET", detail_url, "configuration")
                        if detail is None:
                            state, reason = "inaccessible", "resource_configuration_unavailable"
                        elif canonical_id(detail.get("id", "")) != identity:
                            raise InputError(
                                "Azure configuration identity differs from requested resource"
                            )
                        else:
                            values = properties(kind, detail.get("properties"))
                    resources.append(
                        {
                            "logical_id": identity,
                            "arm_id": identity,
                            "original_arm_id": entry["id"],
                            "resource_type": kind,
                            "properties": values,
                            "state": state,
                            "reason": reason,
                            "api_version": version,
                            "source_location": ORIGIN + entry["id"],
                        }
                    )
            assignment_url = (
                ORIGIN
                + scope
                + "/providers/Microsoft.Authorization/policyAssignments?api-version=2023-04-01"
            )
            all_assignments = self.pages("GET", assignment_url, "assignments")
            # atScope includes inherited assignments; unfiltered lists retain child assignments too.
            all_assignments += self.pages(
                "GET", assignment_url + "&$filter=atScope()", "assignments"
            )
            for entry in all_assignments:
                values = entry.get("properties", {})
                key = canonical_id(entry["id"])
                assignments[key] = {
                    "id": entry["id"],
                    "scope": values.get("scope"),
                    "definition_id": values.get("policyDefinitionId"),
                    "not_scopes": values.get("notScopes", []),
                    "enforcement_mode": values.get("enforcementMode"),
                    "parameters": {
                        name: {"value_sha256": digest(value), "redacted": True}
                        for name, value in values.get("parameters", {}).items()
                    },
                    "resource_selectors": values.get("resourceSelectors", []),
                    "overrides": values.get("overrides", []),
                    "interpretation": "assignment_configuration_not_compliance",
                }
            exemption_url = (
                ORIGIN + scope + "/providers/Microsoft.Authorization/policyExemptions"
                "?api-version=2022-07-01-preview"
            )
            for entry in self.pages("GET", exemption_url, "exemptions"):
                values = entry.get("properties", {})
                expiry = values.get("expiresOn")
                exemptions[canonical_id(entry["id"])] = {
                    "id": entry["id"],
                    "assignment_id": values.get("policyAssignmentId"),
                    "definition_reference_ids": values.get("policyDefinitionReferenceIds", []),
                    "category": values.get("exemptionCategory"),
                    "expires_on": expiry,
                    "expired": bool(expiry and timestamp(expiry) <= timestamp(now())),
                }
            query = (
                ORIGIN
                + scope
                + "/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
                "?api-version=2019-10-01"
            )
            for entry in self.pages("POST", query, "compliance"):
                compliance.append(
                    {
                        key: entry.get(key)
                        for key in (
                            "resourceId",
                            "policyAssignmentId",
                            "policyDefinitionId",
                            "policyDefinitionReferenceId",
                            "complianceState",
                            "timestamp",
                        )
                    }
                )
        bundle_scope = selected or (scopes[0] if len(scopes) == 1 else None)
        self.artifacts["requested-scopes"] = digest(
            {"subscriptions": subscriptions, "management_group": management_group}
        )
        return validate(
            document(
                "evidence",
                mode="observed",
                source="azure",
                collected_at=now(),
                scope=bundle_scope,
                artifact_hashes=self.artifacts,
                resources=resources,
                inventory_complete=self.facets["inventory"] and self.facets["relationships"],
                diagnostics=self.diagnostics,
                metadata={
                    "scopes": scopes,
                    "relationships": relationships,
                    "completeness": self.facets,
                    "run_complete": all(self.facets.values()),
                    "inventory_authorization_attested": inventory_authorized,
                    "policy_assignments": list(assignments.values()),
                    "policy_exemptions": list(exemptions.values()),
                    "policy_compliance": compliance,
                    "policy_warning": (
                        "Configuration, compliance evaluations and human recommendation "
                        "judgments are separate."
                    ),
                    "permissions": "See docs/collection.md; no role or permission is changed.",
                },
            )
        )
