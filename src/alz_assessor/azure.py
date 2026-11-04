"""Explicit-scope read-only ARM collection with injected transport for offline tests."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import parse_qs, urlsplit

from .arm import API_VERSIONS, properties
from .contracts import canonical_id, digest, document, now, scope_id, timestamp, validate
from .terraform import InputError

ORIGIN = "https://management.azure.com"
ARG_URL = ORIGIN + "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
ARG_QUERY = "resources | project id, type"


class TransportError(InputError):
    """A read-only request failed before a service response was available."""


class ResponseLimitError(TransportError):
    """A bounded read could not retain the entire service response."""


@dataclass
class Response:
    status: int
    body: dict[str, Any]
    headers: dict[str, str]


class ReadTransport(Protocol):
    def __call__(
        self,
        method: str,
        url: str,
        body: dict[str, Any] | None = None,
    ) -> Response: ...


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

    def __call__(
        self,
        method: str,
        url: str,
        body: dict[str, Any] | None = None,
    ) -> Response:
        safe_url(url)
        graph = method == "POST" and url == ARG_URL
        policy_query = method == "POST" and urlsplit(url).path.endswith(
            "/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults",
        )
        if method != "GET" and not (policy_query or graph):
            raise InputError("Transport rejects non-read-only operations")
        if graph:
            if (
                not isinstance(body, dict)
                or set(body) != {"subscriptions", "query", "options"}
                or body["query"] != ARG_QUERY
                or not isinstance(body["subscriptions"], list)
                or not body["subscriptions"]
                or not isinstance(body["options"], dict)
                or set(body["options"]) - {"$top", "$skipToken", "resultFormat"}
                or body["options"].get("$top") != 1000
                or body["options"].get("resultFormat") != "objectArray"
            ):
                raise InputError(
                    "ARG requires exact reviewed query and explicit body scope/options"
                )
            for subscription in body["subscriptions"]:
                if not isinstance(subscription, str):
                    raise InputError("ARG subscription identifiers must be strings")
                scope_id("/subscriptions/" + subscription)
            if len(set(body["subscriptions"])) != len(body["subscriptions"]):
                raise InputError("Duplicate ARG subscription scope")
            token = body["options"].get("$skipToken")
            if token is not None and (not isinstance(token, str) or not 0 < len(token) <= 64_000):
                raise InputError("Invalid ARG continuation token")
        elif body is not None:
            raise InputError("Only the reviewed ARG query accepts a request body")
        request = urllib.request.Request(
            url,
            method=method,
            data=json.dumps(body).encode() if graph else b"" if policy_query else None,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                content = response.read(8_000_001)
                if len(content) > 8_000_000:
                    raise ResponseLimitError("Azure response exceeds byte limit")
                data = json.loads(content)
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
        transport: ReadTransport,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.transport, self.sleep = transport, sleep
        self.reset()

    def reset(self) -> None:
        self.definition_members = 0
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
                "definitions",
            )
        }

    def gap(self, facet: str, reason: str, location: str) -> None:
        self.facets[facet] = False
        self.diagnostics.append({"facet": facet, "reason": reason, "source_location": location})

    def request(
        self,
        method: str,
        url: str,
        facet: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        safe_url(url)
        for attempt in range(4):
            try:
                response = (
                    self.transport(method, url, body)
                    if body is not None
                    else self.transport(method, url)
                )
            except ResponseLimitError:
                self.gap(facet, "response_byte_limit", url)
                return None
            except TransportError:
                self.gap(facet, "transport_unavailable", url)
                return None
            if response.status == 200:
                key = method + " " + url + ("#body=" + digest(body) if body is not None else "")
                self.artifacts[key] = digest(response.body)
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
        origin_version = parse_qs(urlsplit(url).query).get("api-version")
        seen = set()
        for _ in range(100):
            if (
                url in seen
                or urlsplit(safe_url(url)).path != origin_path
                or parse_qs(urlsplit(url).query).get("api-version") != origin_version
            ):
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
                total = body.get("totalRecords", body.get("@odata.count"))
                if body.get("resultTruncated") in (True, "true") or (
                    type(total) is int and total > len(items)
                ):
                    self.gap(facet, "truncated_without_continuation", url)
                return items
            if not isinstance(link, str):
                raise InputError("Azure nextLink must be a URL")
            url = link
        self.gap(facet, "page_limit", url)
        return items

    def graph_inventory(self, scopes: list[str]) -> list[dict[str, Any]]:
        if not scopes:
            self.gap("inventory", "arg_no_explicit_subscription_scope", ARG_URL)
            return []
        token = None
        seen = set()
        items: list[dict[str, Any]] = []
        for _ in range(100):
            options: dict[str, Any] = {"$top": 1000, "resultFormat": "objectArray"}
            if token is not None:
                options["$skipToken"] = token
            body = self.request(
                "POST",
                ARG_URL,
                "inventory",
                {
                    "subscriptions": [scope.split("/")[2] for scope in scopes],
                    "query": ARG_QUERY,
                    "options": options,
                },
            )
            if body is None:
                return items
            values, count, total = body.get("data"), body.get("count"), body.get("totalRecords")
            truncated = body.get("resultTruncated")
            if (
                not isinstance(values, list)
                or not all(isinstance(item, dict) for item in values)
                or type(count) is not int
                or count != len(values)
                or type(total) is not int
                or total < count
                or not (
                    type(truncated) is bool
                    or (isinstance(truncated, str) and truncated in {"true", "false"})
                )
            ):
                raise InputError("ARG requires object-array data and explicit counts/truncation")
            for item in values:
                identity = canonical_id(item.get("id", ""))
                if not any(identity.startswith(scope + "/") for scope in scopes):
                    raise InputError("ARG returned a resource outside explicit transport scope")
            items.extend(values)
            if len(items) > 10_000:
                self.gap("inventory", "item_limit", ARG_URL)
                return items[:10_000]
            token = body.get("$skipToken")
            if not token:
                if body["resultTruncated"] in (True, "true") or total > len(items):
                    self.gap("inventory", "truncated_without_continuation", ARG_URL)
                return items
            if not isinstance(token, str) or len(token) > 64_000 or token in seen:
                self.gap("inventory", "invalid_or_repeated_continuation", ARG_URL)
                return items
            seen.add(token)
        self.gap("inventory", "page_limit", ARG_URL)
        return items

    def definition(
        self,
        identity: str,
        scopes: list[str],
        definitions: dict[str, Any],
        initiatives: dict[str, Any],
        depth: int = 0,
    ) -> None:
        if not isinstance(identity, str):
            raise InputError("Policy definition identity must be a string")
        if depth >= 16:
            self.gap("definitions", "definition_reference_depth_limit", identity)
            return
        builtin = re.fullmatch(
            r"/providers/Microsoft.Authorization/(policyDefinitions|policySetDefinitions)/"
            r"[A-Za-z0-9._()-]+",
            identity,
            re.IGNORECASE,
        )
        if builtin:
            key = identity.lower()
        else:
            key = canonical_id(identity)
            if not re.search(
                r"/providers/microsoft.authorization/(policydefinitions|policysetdefinitions)"
                r"/[^/]+$",
                key,
            ):
                raise InputError("Invalid policy definition reference")
            if not any(key.startswith(scope + "/") for scope in scopes):
                self.gap("definitions", "referenced_definition_outside_requested_scope", identity)
                return
        if key in definitions or key in initiatives:
            return
        if len(definitions) + len(initiatives) >= 1000:
            self.gap("definitions", "definition_limit", identity)
            return
        # Reserve the identity before following initiative references; cycles are never expanded.
        target = initiatives if "/policysetdefinitions/" in key else definitions
        target[key] = {"id": identity, "state": "inaccessible"}
        detail = self.request("GET", ORIGIN + identity + "?api-version=2023-04-01", "definitions")
        if detail is None:
            return
        if not isinstance(detail.get("id"), str) or detail["id"].lower() != key:
            raise InputError("Policy definition identity differs from requested reference")
        values = detail.get("properties")
        if not isinstance(values, dict):
            raise InputError("Policy definition properties must be an object")
        target[key] = {
            "id": identity,
            "state": "known",
            "content_sha256": digest(detail),
            "rule_sha256": digest(values.get("policyRule")),
            "interpretation": "definition_configuration_not_compliance",
        }
        if target is initiatives:
            members = values.get("policyDefinitions")
            if not isinstance(members, list) or len(members) > 1000:
                raise InputError("Initiative requires a bounded definition-reference array")
            associations = []
            for member in members:
                if self.definition_members >= 10_000:
                    self.gap("definitions", "definition_member_limit", identity)
                    target[key]["members_complete"] = False
                    break
                self.definition_members += 1
                if not isinstance(member, dict) or not isinstance(
                    member.get("policyDefinitionId"),
                    str,
                ):
                    raise InputError("Invalid initiative member reference")
                reference = member["policyDefinitionId"]
                if "/policydefinitions/" not in reference.lower():
                    raise InputError("Initiative members must reference policy definitions")
                associations.append(
                    {
                        "definition_id": reference,
                        "reference_id_sha256": digest(member.get("policyDefinitionReferenceId")),
                        "parameters_sha256": digest(member.get("parameters")),
                    }
                )
                self.definition(reference, scopes, definitions, initiatives, depth + 1)
            target[key]["members"] = associations

    def collect(
        self,
        *,
        subscriptions: list[str] | None = None,
        management_group: str | None = None,
        inventory_authorized: bool = False,
        resource_graph: bool = False,
    ) -> dict[str, Any]:
        self.reset()
        started = now()
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
        policy_scopes = [selected] if selected else []
        if selected:
            descendants = self.pages(
                "GET", ORIGIN + selected + "/descendants?api-version=2020-05-01", "relationships"
            )
            parents = {}
            for entry in descendants:
                identity = scope_id(entry["id"])
                parent = entry.get("properties", {}).get("parent", {}).get("id")
                if not isinstance(parent, str) or identity in parents or identity == selected:
                    raise InputError("Invalid or conflicting management-group descendant")
                parents[identity] = scope_id(parent)
                if not parents[identity].startswith(
                    "/providers/microsoft.management/managementgroups/",
                ):
                    raise InputError("Descendant parent must be a management group")
            for identity, parent in parents.items():
                visited = {identity}
                ancestor = parent
                while ancestor != selected and ancestor in parents and ancestor not in visited:
                    visited.add(ancestor)
                    ancestor = parents[ancestor]
                if ancestor != selected or "/resourcegroups/" in identity:
                    self.gap("relationships", "unverified_descendant_relationship", identity)
                    continue
                relationships.append({"id": identity, "parent": parent})
                policy_scopes.append(identity)
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
        definitions: dict[str, Any] = {}
        initiatives: dict[str, Any] = {}
        policy_scopes = sorted(set([*policy_scopes, *scopes]))
        graph = self.graph_inventory(scopes) if resource_graph else []
        for scope in policy_scopes:
            if scope.startswith("/subscriptions/"):
                relationships.append(
                    {"id": scope, "relationship": "explicit_or_verified_descendant"}
                )
                inventory = (
                    [
                        entry
                        for entry in graph
                        if canonical_id(entry["id"]).startswith(
                            scope + "/",
                        )
                    ]
                    if resource_graph
                    else self.pages(
                        "GET", ORIGIN + scope + "/resources?api-version=2021-04-01", "inventory"
                    )
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
                record = {
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
                if key in assignments and assignments[key] != record:
                    self.gap("assignments", "conflicting_policy_record", entry["id"])
                    assignments[key] = {"id": entry["id"], "conflict": True}
                else:
                    assignments[key] = record
            exemption_url = (
                ORIGIN + scope + "/providers/Microsoft.Authorization/policyExemptions"
                "?api-version=2022-07-01-preview"
            )
            if scope.startswith("/providers/microsoft.management/"):
                exemption_url += "&$filter=atScope()"
            for entry in self.pages("GET", exemption_url, "exemptions"):
                values = entry.get("properties", {})
                expiry = values.get("expiresOn")
                key = canonical_id(entry["id"])
                record = {
                    "id": entry["id"],
                    "assignment_id": values.get("policyAssignmentId"),
                    "definition_reference_ids": values.get("policyDefinitionReferenceIds", []),
                    "category": values.get("exemptionCategory"),
                    "expires_on": expiry,
                    "expired": bool(expiry and timestamp(expiry) <= timestamp(started)),
                }
                if key in exemptions and exemptions[key] != record:
                    self.gap("exemptions", "conflicting_policy_record", entry["id"])
                    exemptions[key] = {"id": entry["id"], "conflict": True}
                else:
                    exemptions[key] = record
            query = (
                ORIGIN
                + scope
                + "/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
                "?api-version=2019-10-01"
            )
            for entry in self.pages("POST", query, "compliance"):
                resource_identity = canonical_id(entry.get("resourceId", ""))
                if not any(
                    resource_identity == value or resource_identity.startswith(value + "/")
                    for value in policy_scopes
                ):
                    self.gap("compliance", "policy_state_outside_requested_resources", query)
                    continue
                if entry.get("timestamp") is not None:
                    timestamp(entry["timestamp"])
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
            for collection in ("policyDefinitions", "policySetDefinitions"):
                url = (
                    ORIGIN
                    + scope
                    + "/providers/Microsoft.Authorization/"
                    + collection
                    + "?api-version=2023-04-01&$filter=atExactScope()"
                )
                for entry in self.pages("GET", url, "definitions"):
                    self.definition(entry["id"], policy_scopes, definitions, initiatives)
        for assignment in assignments.values():
            if assignment.get("conflict"):
                continue
            reference = assignment.get("definition_id")
            if isinstance(reference, str):
                self.definition(reference, policy_scopes, definitions, initiatives)
            else:
                self.gap("definitions", "assignment_definition_reference_missing", assignment["id"])
        bundle_scope = selected or (scopes[0] if len(scopes) == 1 else None)
        self.artifacts["requested-scopes"] = digest(
            {"subscriptions": subscriptions, "management_group": management_group}
        )
        return validate(
            document(
                "evidence",
                mode="observed",
                source="azure",
                collected_at=started,
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
                    "policy_definitions": list(definitions.values()),
                    "policy_set_definitions": list(initiatives.values()),
                    "inventory_transport": "resource-graph" if resource_graph else "arm-list",
                    "arg_warning": "ARG is eventually consistent; exhausted pages do not prove "
                    "authorization coverage or current completeness of child-resource lists.",
                    "policy_warning": (
                        "Configuration, compliance evaluations and human recommendation "
                        "judgments are separate."
                    ),
                    "permissions": "See docs/collection.md; no role or permission is changed.",
                },
            )
        )
