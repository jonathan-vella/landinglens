"""Shared narrative collection with explicit per-control bound human decisions."""

from typing import Any

from .contracts import control_digest, digest, document, require, scope_id, validate
from .reviews import prepare_reviews, validate_reviews
from .terraform import InputError

BANK_VERSION = "2026-11-05.1"
BANK = {
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
                control: next(c for c in catalog["controls"] if c["control_id"] == control)[
                    "evidence_requirements"
                ]
                for control in controls
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
        {control: controls[control]["evidence_requirements"] for control in seen}
    ):
        raise InputError("Interview requirements binding changed")
    record = document("manual", schema_version="1.1", entries=entries)
    if not validate_reviews(record, catalog, scope, at)["ready_to_apply"]:
        raise InputError("Every interview decision must be current and bound before applying")
    return record
