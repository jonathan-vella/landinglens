"""Shared narrative collection with explicit per-control bound human decisions."""

from typing import Any

from .contracts import control_digest, digest, document, require, scope_id, validate
from .reviews import prepare_reviews, validate_reviews
from .terraform import InputError

BANK_VERSION = "2026-11-06.10"
BANK = {
    "resource-cost-governance": {
        "question": "Describe the scoped process that communicates owner responsibilities and "
        "demonstrates access, budget and policy reviews and remediation. Separately establish "
        "subscription-owner/core-team quota awareness and provisioning impact: quota is not "
        "available regional capacity. Reconcile financial suitability and matching-usage "
        "Reserved Instance discounts separately from accepted on-demand capacity reservation, "
        "VM/SKU/region/zone association and SLA conditions; discounts do not guarantee capacity. "
        "Demonstrate working dashboards or other visualizations covering appropriate CPU, "
        "guest-memory and free-disk capacity, targets and original-time telemetry; tile counts "
        "and disk I/O are not coverage or health. Cite the approved operating cost plan, "
        "accountability, forecast/budget, allocation, agreed reviews and corrective actions. "
        "If server-based identity is applicable, explicitly designate the dedicated identity "
        "subscription/MG and substantiate hosting/isolation and regional AD DS sites/subnets/"
        "locator use or managed Domain Services design; names and parent edges prove no role. "
        "Reconcile approved billing/cost taxonomy and attributable allocation with supported "
        "service/agreement/scope/access and actual tag-inheritance/conflict/time conditions. "
        "Resource tags do not automatically inherit; Cost Management inheritance changes "
        "usage records, not resources or all history. Use redacted references only, never "
        "personal owner/directory records, tag values, raw dashboard queries/content, "
        "billing amounts, usage histories or credentials. Decide all seven canonical GUIDs "
        "separately; configuration or a shared answer alone establishes none.",
        "controls": [
            "ALZ-49b82111-2df2-47ee-912e-7f983f630472",
            "ALZ-2dd69c5b-5c26-422f-94b6-9bad33aad5e8",
            "ALZ-c68e1d76-6673-413b-9f56-64b5e984a859",
            "ALZ-c773e7d2-6162-43a7-95a9-17e1f348ef25",
            "ALZ-ae28c84c-33b6-4b78-88b9-fe5c41049d40",
            "ALZ-3a923c34-74d0-4001-aac6-a9e01e6a83de",
            "ALZ-5de32c19-9248-4160-9d5d-1e4e614658d3",
        ],
    },
    "expressroute-monitoring-routing-failover": {
        "question": "Reconcile actual Insights availability/utilization for both links, peering "
        "and gateway with maintenance interpretation and arriving alerts/output; configured "
        "monitors are not health. Review supported Arc/AMA and Network Watcher agents rather "
        "than the linked retired MMA instructions, complete source/destination/redundant-path "
        "coverage and approved probe frequency/loss/latency requirements. Bind distinct "
        "circuits and exact gateways to actual independent peering/provider/customer failure "
        "domains; configured location-label fingerprints are neither canonical sites nor "
        "physical independence. For single-circuit private peering, reconcile maintained "
        "route-based non-Basic VPN suitability, Internet backup independence and both-direction "
        "preference/failover evidence. Review dynamic edge convergence/load sharing or maintained "
        "active-passive routing, NAT/stateful effects and maintenance draining. Bind both "
        "physical links to distinct real customer devices; verify interface and BGP-linked BFD "
        "on both customer/provider edges with private/Microsoft, IPv4/IPv6 creation/reset dates "
        "and vendor echo behavior. GatewaySubnet propagation has a separate strictly joined "
        "configuration predicate, not an availability/effective-route claim. Use attributable "
        "redacted references, never endpoint addresses, router credentials, raw probes or "
        "fabricated operational tests. Decide these eight human-evidence GUIDs separately; "
        "one answer or cloud-side default creates no whole-recommendation outcome.",
        "controls": [
            "ALZ-b30e38c3-f298-412b-8363-cefe179b599d",
            "ALZ-5bf68dc9-325e-4873-bf88-f8214ef2e5d2",
            "ALZ-e0d5973c-d4cd-421b-8881-37f5e6c4cfd3",
            "ALZ-cf3fe65c-fec0-495a-8edc-9675200f2add",
            "ALZ-d581a947-69a2-4783-942e-9df3664324c8",
            "ALZ-b258f058-b9f6-46cd-b28d-990106f0c3f8",
            "ALZ-fe2a1b53-6fbd-4c67-b58a-85d7c7a0afcb",
            "ALZ-669b215a-ce43-4371-8f6f-11047f6490f1",
        ],
    },
    "dr-dns-bastion": {
        "question": "Reconcile complete production/DR address populations and any Site Recovery "
        "IP-retention/subnet-move exception; actual public-IP SKU/region/API/zone and attached-"
        "service suitability; Azure-only zone ownership/delegation and default/custom DNS; "
        "both-direction hybrid Resolver endpoints, exclusive delegated subnets, rules, regional "
        "links and loop avoidance; workload-specific DNS; VM-primary-NIC-only registration and "
        "other record lifecycles; multi-region failover ownership/TTL/cache/update/rollback "
        "evidence; Windows/container UDP SOURCE port 65330 exclusion evidence; and Bastion "
        "SKU/private-only/legacy subnet/access/bypass/NSG/route/DNS exceptions. Use redacted "
        "evidence references, not DNS records, raw destinations, host inventories, credentials "
        "or recording URLs. Decide all ten GUIDs separately; configuration and one narrative "
        "do not establish outcomes.",
        "controls": [
            "ALZ-f348ef25-4c27-4d42-b8bb-ac7571559ab9",
            "ALZ-0c47f486-656d-4699-8c30-edef5b8a93c4",
            "ALZ-153e8908-ae28-4c84-a33b-6b7808b9fe5c",
            "ALZ-41049d40-3a92-43c3-974d-00018ac6a9e0",
            "ALZ-1e6a83de-5de3-42c1-a924-81607d5d1e4e",
            "ALZ-614658d3-558f-4d77-849b-821112df27ee",
            "ALZ-18c80eb0-582a-4198-bf5c-d8800b2d263b",
            "ALZ-baac3ecb-a94c-4ac4-8c79-cdf27c0d78df",
            "ALZ-ee1ac551-c4d5-46cf-b035-d0a3c50d87ad",
            "ALZ-6eab9eb6-762b-485e-8ea8-15aa5dba0bd0",
        ],
    },
    "expressroute-cost-resilience": {
        "question": "Describe the attributable actual outbound demand and full metered/unlimited/"
        "Direct-port/circuit/gateway/provider cost comparison, including Local reach and Global "
        "Reach restrictions. Reconcile physical peering location with every required workload/"
        "recovery region; resource location and public tables do not attest current availability. "
        "Distinguish AZ-capable SKU from deployed gateway/public-IP zone placement and Azure "
        "active-active from real independent on-premises appliances and failover. Supply actual "
        "throughput/latency and dedicated-port requirements rather than configured bandwidth. "
        "Review FastPath's exact connection/gateway/scale prerequisites, provider versus Direct "
        "IPv4/IPv6 and same-region topology, enrolled limited-GA Private Link services, published "
        "IP limits, fixed-scale guidance and fallback capacity. Reconcile Direct/Local billing "
        "choices and actual dedicated circuits, routing domains, VLAN/VRF/BGP paths and shared "
        "port contention against explicit isolation requirements. Use redacted attributable "
        "references, never addresses, keys or secret/private device identities. Decide each "
        "of the nine canonical GUIDs separately; configuration or one answer alone proves none.",
        "controls": [
            "ALZ-7025b442-f6e9-4af6-b11f-c9574916016f",
            "ALZ-f4e7926a-ec35-476e-a412-5dd17136bd62",
            "ALZ-2447ec66-138a-4720-8f1c-e16ed301d6e8",
            "ALZ-72e52e36-11cc-458b-9a4b-1511e43a58a9",
            "ALZ-c2299c4d-7b57-4d0c-9555-62f2b3e4563a",
            "ALZ-4d873974-8b66-42d6-b15f-512a65498f6d",
            "ALZ-45866df8-cf85-4ca9-bbe2-65ec1478919e",
            "ALZ-718cb437-b060-2589-8856-2e93a5c6633b",
            "ALZ-8042d88e-79d1-47b7-9b22-a5a67e7a8ed4",
        ],
    },
    "sovereign-audit-workload-protection": {
        "question": "Describe approved sovereign key-custody requirements and actual compatible "
        "CMK use: Managed HSM keys are not secrets/credentials, and external KEK custody adds "
        "customer-run HSM/proxy responsibilities. Identify actual redacted Entra access-audit "
        "reports separately from Azure activity logs. Reconcile all applicable subscriptions' "
        "activity categories, successful ingestion/export and table/storage retention with "
        "approved requirements; configuration and new-arrival export do not prove history. "
        "Distinguish paid CSPM, Servers P1/P2 and workload-specific plans/components, "
        "resource overrides, actual coverage and endpoint enforcement. Reconcile Update "
        "Manager assessment success and base-OS patch drift against the approved baseline "
        "rather than deprecated MMA or a guessed threshold. Use attributable redacted "
        "evidence references, never credentials, keys, security domains or private audit/"
        "endpoint records. Decide all eight canonical GUIDs separately; one answer, "
        "pricing record or diagnostic flag alone establishes no outcome.",
        "controls": [
            "ALZ-4ac6b67c-b3a4-4ff9-8e87-b07a7ce7bbdb",
            "ALZ-4e5695f2-223a-4ce8-ab12-308ca5017f15",
            "ALZ-4e3ab369-3829-4e7e-9161-83687a0477a2",
            "ALZ-09945bda-4333-44f2-9911-634182ba5275",
            "ALZ-36a72a48-fffe-4c40-9747-0ab5064355ba",
            "ALZ-77425f48-ecba-43a0-aeac-a3ac733ccc6a",
            "ALZ-24d96b30-61ee-4436-a1cc-d6ef08bc574b",
            "ALZ-15833ee7-ad6c-46d3-9331-65c7acbe44ab",
        ],
    },
    "inbound-outbound-hybrid": {
        "question": "Describe global Front Door policy/domain/route coverage and effective rules; "
        "both origin backend filtering and exact X-Azure-FDID rejection; workload-aligned proxy "
        "placement; every supported public IP's DDoS protection and arriving diagnostics; "
        "the approved explicit-outbound migration strategy with current API/existing-network "
        "scope (not the frozen retirement date); actual NIC-deny policy assignment/version/"
        "enforcement and independent exceptions; maintained primary ExpressRoute/backup VPN "
        "suitability; both-direction BGP preference; and measured demand supporting gateway "
        "SKU/generation. Reference redacted evidence, not header values, hosts, peer addresses "
        "or secrets. Decide all ten GUIDs separately, including both D05.08 meanings. "
        "Configuration or one shared answer alone establishes none of these outcomes.",
        "controls": [
            "ALZ-1d7aa9b6-4704-4489-a804-2d88e79d17b7",
            "ALZ-3b22a5a6-7e7a-48ed-9b30-e38c3f29812b",
            "ALZ-2363cefe-179b-4599-be0d-5973cd4cd21b",
            "ALZ-088137f5-e6c4-4cfd-9e50-4547c2447ec6",
            "ALZ-b034c01e-110b-463a-b36e-e3346e57f225",
            "ALZ-b1c82a3f-2320-4dfa-8972-7ae4823c8930",
            "ALZ-3c5a808d-c695-4c14-a63c-c7ab7a510e41",
            "ALZ-359c373e-7dd6-4162-9a36-4a907ecae48e",
            "ALZ-f29812b2-363c-4efe-879b-599de0d5973c",
            "ALZ-d4cd21b0-8813-47f5-b6c4-cfd3e504547c",
        ],
    },
    "access-operating-model": {
        "question": "Describe the approved RBAC scope/operating model and group source of "
        "authority; actual managed-identity use; administrator work/school account provenance; "
        "Conditional Access and MFA coverage, exclusions and evaluation evidence; and PIM "
        "eligible/active/permanent grants, activation limits and accepted responsibilities. "
        "Use redacted evidence references, not principal names, user records or credentials. "
        "Decide each canonical GUID separately, including the two distinct B03.02 entries. "
        "Configuration, one sign-in or an interview answer alone establishes no enforcement.",
        "controls": [
            "ALZ-348ef254-c27d-442e-abba-c7571559ab91",
            "ALZ-4348bf81-7573-4512-8f46-9061cc198fea",
            "ALZ-12e7f983-f630-4472-8dd6-9c5b5c2622f5",
            "ALZ-4b69bad3-3aad-45e8-a68e-1d76667313b4",
            "ALZ-53e8908a-e28c-484c-93b6-b7808b9fe5c4",
            "ALZ-1049d403-a923-4c34-94d0-0018ac6a9e01",
            "ALZ-e6a83de5-de32-4c19-a248-1607d5d1e4e6",
            "ALZ-14658d35-58fd-4772-99b8-21112df27ee4",
        ],
    },
    "vault-operating-model": {
        "question": "Describe how applications use, partition, access, privately reach and audit "
        "Key Vault. Give redacted evidence references and record a separate decision for each "
        "selected recommendation; neither a vault's existence nor a shared answer proves them.",
        "controls": [
            "ALZ-5017f154-e3ab-4369-9829-e7e316183687",
            "ALZ-a0477a20-9945-4bda-9333-4f2491163418",
            "ALZ-dc055bcf-619e-48a1-9f98-879525d62688",
            "ALZ-cdb3751a-b2ab-413a-ba6e-55d7d8a2adb1",
            "ALZ-17d6326a-f625-4ca4-9e56-95f2223ace8c",
        ],
    },
    "private-service-paths": {
        "question": "Describe shared PaaS private endpoints and the on-premises private-peering "
        "path, including subresource approval, DNS, routes, return path and public-access gaps. "
        "Reference redacted path evidence and decide each selected recommendation separately.",
        "controls": [
            "ALZ-e43a58a9-c229-49c4-b7b5-7d0c655562f2",
            "ALZ-b3e4563a-4d87-4397-98b6-62d6d15f512a",
        ],
    },
}
FIELDS = ("reviewer", "rationale", "evidence", "valid_from", "valid_until")


def question_bank(catalog: dict[str, Any]) -> dict[str, Any]:
    validate(catalog, "catalog")
    controls = {control["control_id"]: control for control in catalog["controls"]}
    questions = []
    for identity, item in BANK.items():
        if any(
            control not in controls or controls[control].get("rule") for control in item["controls"]
        ):
            raise InputError("Question bank requires its exact retained human-evidence controls")
        questions.append(
            {
                "id": identity,
                "question": item["question"],
                "controls": [
                    {
                        "control_id": control,
                        "recommendation": controls[control]["recommendation"],
                        "evidence_requirements": controls[control]["evidence_requirements"],
                        "limitations": controls[control]["rationale"],
                    }
                    for control in item["controls"]
                ],
            }
        )
    return {
        "schema_version": "1.0",
        "kind": "question-bank",
        "version": BANK_VERSION,
        "questions": questions,
        "warning": "Answers alone never establish an outcome.",
    }


def prepare_interview(
    assessment: dict[str, Any],
    catalog: dict[str, Any],
    question_id: str,
    scope: str,
    selected: list[str] | None = None,
) -> dict[str, Any]:
    question_bank(catalog)
    if question_id not in BANK:
        raise InputError("Unknown reviewed interview question")
    controls = selected if selected is not None else BANK[question_id]["controls"]
    if (
        not isinstance(controls, list)
        or not controls
        or any(not isinstance(control, str) for control in controls)
        or len(set(controls)) != len(controls)
        or any(control not in BANK[question_id]["controls"] for control in controls)
    ):
        raise InputError("Interview selection must be unique canonical controls from its question")
    prepared = prepare_reviews(assessment, catalog, controls, scope)
    return {
        "schema_version": "1.0",
        "kind": "interview-response",
        "bank_version": BANK_VERSION,
        "catalog_sha256": digest(catalog),
        "question_id": question_id,
        "scope": scope_id(scope),
        "answer": None,
        **{field: None for field in FIELDS},
        "decisions": [
            {
                "control_id": entry["control_id"],
                "control_sha256": entry["control_sha256"],
                "outcome": None,
            }
            for entry in prepared["entries"]
        ],
        "requirements_sha256": digest(
            {
                "scope": scope_id(scope),
                "controls": {
                    control: next(c for c in catalog["controls"] if c["control_id"] == control)[
                        "evidence_requirements"
                    ]
                    for control in controls
                },
            }
        ),
    }


def compile_interview(
    response: Any,
    catalog: dict[str, Any],
    *,
    at: str | None = None,
) -> dict[str, Any]:
    question_bank(catalog)
    if (
        not isinstance(response, dict)
        or set(response)
        != {
            "schema_version",
            "kind",
            "bank_version",
            "catalog_sha256",
            "question_id",
            "scope",
            "answer",
            *FIELDS,
            "decisions",
            "requirements_sha256",
        }
        or response.get("schema_version") != "1.0"
        or response.get("kind") != "interview-response"
    ):
        raise InputError("Expected interview-response contract 1.0 with exact fields")
    if response["bank_version"] != BANK_VERSION or response["catalog_sha256"] != digest(catalog):
        raise InputError("Interview bank/catalog changed; prepare a new response")
    question_id = require(response, "question_id", str)
    if question_id not in BANK:
        raise InputError("Unknown reviewed interview question")
    scope = scope_id(require(response, "scope", str))
    answer = require(response, "answer", str)
    if len(answer) > 4000:
        raise InputError("Interview answer exceeds 4,000 characters")
    for field in FIELDS:
        if len(require(response, field, str)) > (200 if field == "reviewer" else 4000):
            raise InputError("Interview review field exceeds bounds")
    if len(answer.strip() + "\n\n" + response["rationale"].strip()) > 4000:
        raise InputError("Combined interview answer and rationale exceed review field bounds")
    decisions = require(response, "decisions", list)
    if not decisions or len(decisions) > len(BANK[question_id]["controls"]):
        raise InputError("Interview requires bounded explicitly selected decisions")
    controls = {control["control_id"]: control for control in catalog["controls"]}
    seen = set()
    entries = []
    for decision in decisions:
        if not isinstance(decision, dict) or set(decision) != {
            "control_id",
            "control_sha256",
            "outcome",
        }:
            raise InputError("Supply exact per-control interview outcome and binding")
        identity = require(decision, "control_id", str)
        if identity not in BANK[question_id]["controls"] or identity in seen:
            raise InputError("Unknown or duplicate interview control")
        seen.add(identity)
        if decision["control_sha256"] != control_digest(controls[identity]):
            raise InputError("Interview control content changed")
        entries.append(
            {
                **decision,
                "scope": scope,
                **{field: response[field].strip() for field in FIELDS},
                "rationale": answer.strip() + "\n\n" + response["rationale"].strip(),
            }
        )
    if response["requirements_sha256"] != digest(
        {
            "scope": scope,
            "controls": {control: controls[control]["evidence_requirements"] for control in seen},
        }
    ):
        raise InputError("Interview requirements binding changed")
    record = document("manual", schema_version="1.1", entries=entries)
    if not validate_reviews(record, catalog, scope, at)["ready_to_apply"]:
        raise InputError("Every interview decision must be current and bound before applying")
    return record
