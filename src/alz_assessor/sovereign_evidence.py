"""Source-qualified sovereign review preparation, never organizational or legal assurance."""

from typing import Any

from .contracts import identity_type
from .governance_evidence import MG_KIND, TAG_KINDS, VM_KIND, hierarchy_context, resource_in_scope
from .network_evidence import review_fact
from .protection_evidence import typed_reference
from .sources import unknown

GUIDS = {
    "6cc0ea22-42bb-441e-a345-804ab0a09666",
    "250d81ce-8bbe-4f85-9051-6a18a8221e50",
    "19ca3f89-397d-44b1-b5b6-5e18661372ac",
    "4c27d42e-8bba-4c75-9155-9ab9153e8908",
    "914b8cb7-c2f6-40fa-ae18-81c049e0cb5a",
    "51a1e9e9-a49a-40b2-87b9-ff753bc6de86",
    "a89153d8-18b2-4caf-bc19-850fc8fba00f",
}
POLICY_GUIDS = {
    "5a917e1f-348e-4f25-9c27-d42e8bbac757",
    "78b22132-b41c-460b-a4d3-df8f73a67dc2",
}
LOCATION_GUIDS = {
    "9b461617-db7b-4399-8ac6-d4eb7153893a",
    "bfaf7b7a-9e6c-4840-a2bd-2c524326bdf6",
}
BUDGET_GUID = "29fd366b-a180-452b-9bd7-954b7700c667"
REQUIREMENT_GUIDS = (
    POLICY_GUIDS
    | LOCATION_GUIDS
    | {
        BUDGET_GUID,
        "caeea0e9-1024-41df-a52e-d99c3f22a6f4",
        "3105633e-b168-4ce0-a016-5f10e7cdea5a",
        "77cf1acd-16b4-4092-8d30-6ec9579854ce",
    }
)
REQUIREMENTS_WARNING = (
    "Source-qualified original-time partial configuration only. No budget delivery/spend "
    "enforcement, sovereign initiative identity/version/effective enforcement, approved "
    "jurisdiction, all processing/backup/control/support locations, service availability, "
    "vendor/personnel eligibility or in-use confidential-computing assurance. Requirements, "
    "objectives, access and confidentiality decisions remain independently human."
)
WARNING = (
    "Original-time partial configuration only. No organizational role/root designation, "
    "classification, physical/legal independence, appropriate region, DR, service/feature "
    "availability, entitlement, quota, capacity, policy enforcement or sovereignty assurance."
)


def resource_paths(kind: str) -> set[str]:
    kind = kind.lower()
    return (
        ({"managementParentId"} if kind == MG_KIND else set())
        | ({"resourceLocation"} if kind == VM_KIND else set())
        | (
            {"storageRedundancySummary", "storageEncryptionSummary"}
            if kind == "microsoft.storage/storageaccounts"
            else set()
        )
        | ({"tagCount"} if kind in TAG_KINDS else set())
    )


def configuration_context(
    resource: dict[str, Any],
    by_id: dict[str, list[dict[str, Any]]],
    bundle: dict[str, Any],
    paths: list[str],
) -> dict[str, Any]:
    def known(identity: Any, kind: str) -> dict[str, Any] | None:
        ref = typed_reference(identity, (kind,))
        parts = ref.split("/") if isinstance(ref, str) else []
        size = (
            5
            if kind in {MG_KIND, "microsoft.resources/resourcegroups"}
            else (3 if kind == "microsoft.resources/subscriptions" else 9)
        )
        matches = by_id.get(ref, []) if isinstance(ref, str) else []
        if (
            len(parts) != size
            or (size == 9 and (parts[1] != "subscriptions" or parts[3] != "resourcegroups"))
            or len(matches) != 1
            or matches[0].get("state") != "known"
            or matches[0].get("resource_type", "").lower() != kind
            or not resource_in_scope(matches[0], bundle)
        ):
            return None
        return matches[0]

    kind = resource["resource_type"].lower()
    selected_paths = resource_paths(kind).intersection(paths)
    if not selected_paths or known(resource.get("arm_id"), kind) is not resource:
        return unknown("sovereign_configuration_not_unique_known_typed_selected_scope")
    if sum(r["resource_type"].lower() == kind for r in bundle["resources"]) > 100:
        return unknown("sovereign_configuration_population_over_100")
    facts = {path: review_fact(resource["properties"], path) for path in sorted(selected_paths)}
    if "managementParentId" in facts:
        parent = facts["managementParentId"]
        hierarchy = hierarchy_context(bundle)
        supplied_parent = next(
            (
                edge["parent"]
                for edge in hierarchy["relationships"]
                if edge["id"] == resource["arm_id"].lower()
            ),
            None,
        )
        if (
            parent == resource["arm_id"].lower()
            or known(parent, MG_KIND) is None
            or identity_type(bundle["scope"]) != MG_KIND
            or "unknown" in hierarchy
            or supplied_parent != parent
        ):
            facts["managementParentId"] = unknown(
                "management_parent_join_missing_ambiguous_unbound_or_conflicting"
            )
    return {"facts": facts, "warning": WARNING}
