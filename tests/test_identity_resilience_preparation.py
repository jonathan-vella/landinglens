import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import API_VERSIONS, PLANNED_API_VERSIONS, arm_source, properties
from alz_assessor.bicep import compile_bicep
from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.identity_evidence import (
    DEFINITION_KIND,
    DOMAIN_KIND,
    PATHS,
    SET_KIND,
    VM_KIND,
    assignable_scope_count,
    replica_configuration,
    replica_fact,
)
from alz_assessor.interviews import BANK, compile_interview, prepare_interview
from alz_assessor.network_evidence import review_fact
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import review_context
from alz_assessor.sources import TF_TYPES, terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError, tree_hash
from alz_assessor.tiers import has_fact

ROOT = Path(__file__).resolve().parents[1]
PREPARATION = ROOT / "references" / "preparation"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
SCOPE = SUB + "/resourcegroups/resilience"
VM = SCOPE + "/providers/microsoft.compute/virtualmachines/not-a-domain-controller"
AVAILABILITY = SCOPE + "/providers/microsoft.compute/availabilitysets/authored"
DEFINITION = (
    SCOPE
    + "/providers/microsoft.authorization/roledefinitions/11111111-1111-1111-1111-111111111111"
)
ASSIGNMENT = SCOPE + "/providers/microsoft.authorization/roleassignments/authored"
DOMAIN = SCOPE + "/providers/microsoft.aad/domainservices/authored"
SUBNET = SCOPE + "/providers/microsoft.network/virtualnetworks/primary/subnets/replica"
SECOND = SCOPE + "/providers/microsoft.network/virtualnetworks/secondary/subnets/replica"
AT = "2026-11-06T14:00:00Z"
SENTINEL = "PRIVATE-NOT-FOR-REPORTING"
GUIDS = {
    "B03.08": "d98d954d-7d1c-4a07-92a7-cf3afe8dcbd2",
    "B03.09": "1559ab91-53e8-4908-ae28-c84c33b6b780",
    "B03.10": "e8aa1e41-870d-4968-94c6-77be14f510ac",
    "B03.11": "f5664b5e-984a-4859-a773-e7d261623a76",
    "B03.12": "8b9fe5c4-1049-4d40-9a92-3c3474d00018",
    "B03.13": "0dd4e625-9c4b-4a56-b54a-4357bac12761",
    "B03.14": "1cf0b8da-70bd-44d0-94af-8d99cfc89ae1",
    "B03.15": "984a859c-773e-47d2-9162-3a765a917e1f",
}


class IdentityResiliencePreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def matrix(self):
        return json.loads((PREPARATION / "batch-05.json").read_text("utf-8"))

    def catalog(self):
        catalog = copy.deepcopy(load_catalog())
        rows = {r["guid"]: r for r in self.matrix()["recommendations"]}
        catalog["review_state"] = "authored-preparation-fixture-not-published"
        for control in catalog["controls"]:
            if control["upstream_guid"] not in rows:
                continue
            row = rows[control["upstream_guid"]]
            for field in ("review_resource_types", "review_fact_paths", "evidence_requirements"):
                if field in row:
                    control[field] = copy.deepcopy(row[field])
            control["rationale"] = row["limitations"]
        return validate(catalog, "catalog")

    def own(self, report):
        return [r for r in report["results"] if r["upstream_id"] in GUIDS]

    def control(self, display):
        return next(c for c in self.catalog()["controls"] if c["upstream_id"] == display)

    def record(self, kind, identity, values, top=None):
        return {
            "logical_id": identity,
            "arm_id": identity,
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://authored-resilience",
            "properties": properties(kind, values, root=top),
        }

    def bundle(self):
        resources = [
            self.record(
                VM_KIND,
                VM,
                {"availabilitySet": {"id": AVAILABILITY}, "osProfile": {SENTINEL: SENTINEL}},
                {"location": "West Europe", "zones": [], "tags": {SENTINEL: SENTINEL}},
            ),
            self.record(
                SET_KIND,
                AVAILABILITY,
                {"platformFaultDomainCount": 2, "platformUpdateDomainCount": 5},
                {"location": "westeurope"},
            ),
            self.record(
                DEFINITION_KIND,
                DEFINITION,
                {
                    "type": "CustomRole",
                    "assignableScopes": [SCOPE],
                    "roleName": SENTINEL,
                    "permissions": [{"actions": [SENTINEL]}],
                },
            ),
            self.record(
                "Microsoft.Authorization/roleAssignments",
                ASSIGNMENT,
                {
                    "principalType": "Group",
                    "roleDefinitionId": DEFINITION,
                    "principalId": SENTINEL,
                },
            ),
            self.record(
                DOMAIN_KIND,
                DOMAIN,
                {
                    "sku": "Enterprise",
                    "replicaSets": [
                        {"location": "westeurope", "subnetId": SUBNET},
                        {"location": "northeurope", "subnetId": SECOND},
                    ],
                    "domainName": SENTINEL,
                    "ldapsSettings": {"pfxCertificate": SENTINEL},
                    "notificationSettings": {"additionalRecipients": [SENTINEL]},
                    "configDiagnostics": {SENTINEL: SENTINEL},
                },
                {"location": "westeurope"},
            ),
            self.record(
                "Microsoft.Network/virtualNetworks/subnets",
                SUBNET,
                {"addressPrefix": "10.0.0.0/24"},
            ),
        ]
        return document(
            "evidence",
            schema_version="1.1",
            mode="observed",
            source="saved",
            collected_at=AT,
            scope=SCOPE,
            inventory_complete=False,
            artifact_hashes={"authored-fixture": "0" * 64},
            diagnostics=[],
            resources=resources,
        )

    def test_exact_eight_guids_sources_terms_and_no_accepted_activation(self):
        fixed = ROOT / "references" / "recommendation-batches" / "targets.json"
        self.assertEqual(
            hashlib.sha256(fixed.read_bytes()).hexdigest(),
            "582fe02feee03b50961e5548fa7551bbd3d8729fbcb68f51837d548e59eaa291",
        )
        self.assertEqual(
            {
                row["upstream_id"]: row["guid"]
                for row in json.loads(fixed.read_text())["targets"]
                if row["batch"] == "05"
            },
            GUIDS,
        )
        matrix = self.matrix()
        self.assertEqual(matrix["review_state"], "source-reviewed-preparation-not-accepted")
        self.assertNotIn("catalog_version", matrix)
        self.assertNotIn("accepted_at", matrix)
        self.assertFalse((fixed.parent / "batch-05.json").exists())
        rows = matrix["recommendations"]
        self.assertEqual({r["upstream_id"]: r["guid"] for r in rows}, GUIDS)
        sources = json.loads((PREPARATION / "batch-05-sources.json").read_text())["sources"]
        by_id = {s["id"]: s for s in sources}
        self.assertEqual(len(sources), 25)
        for source in sources:
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["reuse"])
            self.assertTrue(source["finding"])
            self.assertTrue(source["retrieved_at"])
        self.assertIn("/example-scenario/", by_id["ad-ds-availability"]["resolved_url"])
        for identity in ("emergency-access", "entra-log-integration"):
            self.assertIn("/entra/", by_id[identity]["resolved_url"])
        for row in rows:
            self.assertTrue(set(row["sources"]) <= set(by_id))
            self.assertEqual(
                row["classification"], "manual" if row["upstream_id"] == "B03.12" else "assisted"
            )
            self.assertNotIn("rule", row)
            self.assertTrue(row["limitations"])
        current = load_catalog()
        self.assertEqual(len(current["controls"]), 255)
        for control in current["controls"]:
            if control["upstream_guid"] in GUIDS.values():
                self.assertIsNone(control["rule"])
                self.assertNotIn("review_fact_paths", control)
        self.assertFalse(
            any(set(q["controls"]) & {"ALZ-" + g for g in GUIDS.values()} for q in BANK.values())
        )

    def test_minimized_vm_zones_availability_sets_and_explicit_counts(self):
        props = self.bundle()["resources"][0]["properties"]
        self.assertEqual(props["configuredZones"], [])
        self.assertEqual(props["availabilitySetId"], AVAILABILITY)
        self.assertEqual(props["resourceLocation"], "westeurope")
        self.assertNotIn(SENTINEL, json.dumps(self.bundle()))
        for value in (None, True, 0, 4, -1, "2", 2.0):
            fact = properties(SET_KIND, {"platformFaultDomainCount": value})
            self.assertIn("unknown", fact["platformFaultDomainCount"])
        for value in (None, True, 0, 21, "5", 5.0):
            self.assertIn(
                "unknown",
                properties(SET_KIND, {"platformUpdateDomainCount": value})[
                    "platformUpdateDomainCount"
                ],
            )
        for raw in (None, {}, DOMAIN, SUBNET, True):
            value = tf_properties("azurerm_windows_virtual_machine", {"availability_set_id": raw})
            self.assertIn("unknown", value["availabilitySetId"])
        for raw in (None, True, [], ["1"], 1, "4"):
            value = tf_properties("azurerm_linux_virtual_machine", {"zone": raw})
            self.assertIn("unknown", value["configuredZones"])
        absent = tf_properties("azurerm_linux_virtual_machine", {})
        self.assertNotIn("configuredZones", absent)
        self.assertNotIn("availabilitySetId", absent)
        explicit = properties(VM_KIND, {}, root={"zones": []})
        self.assertEqual(explicit["configuredZones"], [])

    def test_replica_shapes_subsets_bounds_and_private_payload_projection(self):
        props = self.bundle()["resources"][4]["properties"]
        replicas = props["replicaConfiguration"]
        self.assertEqual(replicas["replicaCount"], 2)
        self.assertEqual(replicas["population"], "supplied-arm-list")
        self.assertEqual(replica_fact(replicas), replicas)
        for raw in (
            None,
            {},
            [None],
            [{"location": "westeurope", "subnetId": DOMAIN}],
            [{"location": True, "subnetId": SUBNET}],
            [{"location": "west", "subnetId": SUBNET}] * 2,
            [{"location": "west", "subnetId": SUBNET}] * 6,
        ):
            self.assertFalse(has_fact(replica_configuration(raw, "supplied-arm-list")))
        for field, raw in (("replicaCount", True), ("replicaCount", 3), ("population", {})):
            self.assertIn("unknown", replica_fact({**replicas, field: raw}))
        initial = tf_properties(
            "azurerm_active_directory_domain_service",
            {
                "sku": "Enterprise",
                "location": "West Europe",
                "domain_name": SENTINEL,
                "secure_ldap": [{"pfx_certificate": SENTINEL}],
                "initial_replica_set": [{"subnet_id": SUBNET}],
            },
        )
        self.assertEqual(initial["replicaConfiguration"]["replicaCount"], 1)
        self.assertEqual(initial["replicaConfiguration"]["population"], "terraform-initial-only")
        self.assertNotIn(SENTINEL, json.dumps(initial))
        for value in (None, [], [{}, {}], [{"subnet_id": VM}]):
            initial = tf_properties(
                "azurerm_active_directory_domain_service",
                {"location": "westeurope", "initial_replica_set": value},
            )
            self.assertIn("unknown", initial["replicaConfiguration"])
        self.assertNotIn("azurerm_active_directory_domain_service_replica_set", TF_TYPES)

    def test_role_definition_shape_privacy_uuid_and_unsupported_scope(self):
        props = self.bundle()["resources"][2]["properties"]
        self.assertEqual(props, {"azureRoleType": "CustomRole", "assignableScopeCount": 1})
        for value in (None, [], {}, [SCOPE, SCOPE.upper()], ["/"], [SCOPE] * 101, [True]):
            self.assertIn("unknown", assignable_scope_count(value))
        values = {
            "scope": SCOPE,
            "role_definition_id": DEFINITION.rsplit("/", 1)[1],
            "name": SENTINEL,
        }
        self.assertEqual(tf_resource_id(SCOPE, "azurerm_role_definition", values), DEFINITION)
        for changed in (
            {**values, "scope": SUB},
            {**values, "role_definition_id": None},
            {**values, "role_definition_id": SENTINEL},
            {"scope": SCOPE, "name": "not-an-arm-id"},
        ):
            self.assertIsNone(tf_resource_id(SCOPE, "azurerm_role_definition", changed))
        self.assertNotIn(
            "azureRoleType", properties("Microsoft.Graph/roleDefinitions", {"type": "CustomRole"})
        )

    def test_known_unique_scoped_joins_never_create_dc_or_directory_assurance(self):
        bundle = self.bundle()
        context = review_context(self.control("B03.09"), bundle)
        vm = next(r for r in context["resources"] if r["resource_type"] == VM_KIND)
        self.assertEqual(vm["linked_availabilitySetId"][0]["facts"]["platformFaultDomainCount"], 2)
        context = review_context(self.control("B03.11"), bundle)
        role = next(r for r in context["resources"] if r["arm_id"] == ASSIGNMENT)
        self.assertEqual(role["linked_roleDefinitionId"][0]["facts"]["azureRoleType"], "CustomRole")
        replica = review_context(self.control("B03.13"), bundle)["resources"][0]
        self.assertEqual(len(replica["linked_subnets"]), 2)
        self.assertIn("unknown", replica["linked_subnets"][1])
        for index, display, path in (
            (1, "B03.09", "availabilitySetId"),
            (2, "B03.11", "roleDefinitionId"),
        ):
            for state in ("unknown", "denied", "unavailable"):
                changed = copy.deepcopy(bundle)
                changed["resources"][index]["state"] = state
                changed["resources"][index]["reason"] = "fixture_" + state
                # The shared evidence contract accepts known/unknown records only.
                if state != "unknown":
                    changed["resources"][index]["state"] = "unknown"
                    changed["resources"][index]["reason"] = state
                context = review_context(self.control(display), changed)
                linked = [
                    r["linked_" + path] for r in context["resources"] if "linked_" + path in r
                ]
                self.assertTrue(any("unknown" in row[0] for row in linked))
            changed = copy.deepcopy(bundle)
            changed["resources"].append(copy.deepcopy(changed["resources"][index]))
            changed["resources"][-1]["logical_id"] += "-duplicate"
            with self.assertRaisesRegex(InputError, "Duplicate or ambiguous ARM resource identity"):
                review_context(self.control(display), changed)
        for row in self.own(assess(bundle, self.catalog(), at=AT, evidence_tiers=True)):
            self.assertNotEqual(row["observed"]["outcome"], "pass")
            self.assertNotEqual(row["observed"]["evidence_tier"], "verified")

    def test_foreign_unbound_wrong_type_stale_and_truncated_remain_explicit(self):
        bundle = self.bundle()
        for transform in ("foreign", "unbound", "wrong_type"):
            changed = copy.deepcopy(bundle)
            for record in changed["resources"]:
                if transform == "foreign":
                    record["arm_id"] = record["arm_id"].replace(
                        SCOPE, SUB + "/resourcegroups/foreign"
                    )
                elif transform == "unbound":
                    record["arm_id"] = None
                else:
                    record["arm_id"] = DOMAIN
            if transform == "wrong_type":
                with self.assertRaisesRegex(InputError, "Resource type does not match"):
                    review_context(self.control("B03.09"), changed)
                continue
            context = review_context(self.control("B03.09"), changed)
            self.assertEqual(context["matching_resources"], 0)
            self.assertEqual(context["unbound_resources"], 2)
            rows = self.own(assess(changed, self.catalog(), at=AT, evidence_tiers=True))
            self.assertTrue(all(r["observed"]["evidence_tier"] != "signal" for r in rows))
        changed = copy.deepcopy(bundle)
        changed["resources"] = [copy.deepcopy(bundle["resources"][0]) for _ in range(101)]
        for index, resource in enumerate(changed["resources"]):
            resource["logical_id"] += str(index)
            resource["arm_id"] += str(index)
        context = review_context(self.control("B03.09"), changed)
        self.assertTrue(context["truncated"])
        self.assertEqual(context["matching_resources"], 101)
        self.assertEqual(len(context["resources"]), 100)
        for timestamp in ("2000-01-01T00:00:00Z", "2030-01-01T00:00:00Z"):
            changed = copy.deepcopy(bundle)
            changed["collected_at"] = timestamp
            rows = self.own(assess(changed, self.catalog(), at=AT, evidence_tiers=True))
            self.assertTrue(all(r["observed"]["evidence_tier"] != "signal" for r in rows))

    def tf_values(self):
        return {
            "azurerm_windows_virtual_machine": {
                "name": "not-a-domain-controller",
                "resource_group_name": "resilience",
                "location": "westeurope",
                "zone": "1",
                "admin_password": SENTINEL,
            },
            "azurerm_availability_set": {
                "name": "authored",
                "resource_group_name": "resilience",
                "location": "westeurope",
                "platform_fault_domain_count": 2,
                "platform_update_domain_count": 5,
            },
            "azurerm_role_definition": {
                "name": SENTINEL,
                "scope": SCOPE,
                "role_definition_id": DEFINITION.rsplit("/", 1)[1],
                "assignable_scopes": [SCOPE],
                "permissions": [{"actions": [SENTINEL]}],
            },
            "azurerm_active_directory_domain_service": {
                "name": "authored",
                "resource_group_name": "resilience",
                "location": "westeurope",
                "domain_name": SENTINEL,
                "sku": "Enterprise",
                "initial_replica_set": [{"subnet_id": SUBNET}],
            },
        }

    def plan(self):
        rows = []
        for kind, body in self.tf_values().items():
            identity = tf_resource_id(SCOPE, kind, body)
            values = {**body, "id": identity}
            if kind == "azurerm_role_definition":
                values.update(role_definition_resource_id=identity, id=identity + "|" + SCOPE)
            if kind == "azurerm_active_directory_domain_service":
                values.update(
                    resource_id=identity,
                    id=identity + "/initialReplicaSetId/22222222-2222-2222-2222-222222222222",
                )
            rows.append(
                {"mode": "managed", "type": kind, "address": kind + ".test", "values": values}
            )
        return {"format_version": "1.2", "planned_values": {"root_module": {"resources": rows}}}

    def test_raw_supplied_module_and_plan_share_minimized_types_without_transport(self):
        self.write(
            "module/main.tf.json",
            {"resource": {k: {"test": v} for k, v in self.tf_values().items()}},
        )
        self.write(
            "source/main.tf.json",
            {
                "module": {
                    "identity": {"source": "example.invalid/resilience/azurerm", "version": "1.0.0"}
                }
            },
        )
        manifest = self.write(
            "snapshots.json",
            {
                "modules": [
                    {
                        "source": "example.invalid/resilience/azurerm",
                        "version": "1.0.0",
                        "subdirectory": "",
                        "path": "module",
                        "sha256": tree_hash(self.root / "module"),
                    }
                ]
            },
        )
        path = self.write("plan.json", self.plan())
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            raw = terraform_source(
                self.root / "source",
                scope=SCOPE,
                provider_version="4.50.0",
                snapshots=manifest,
                authorized_roots=[self.root],
            )
            planned = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        self.assertEqual(
            {r["resource_type"] for r in raw["resources"]}, {TF_TYPES[k] for k in self.tf_values()}
        )
        for bundle in (raw, planned):
            self.assertNotIn(SENTINEL, json.dumps(bundle))
            self.assertTrue(all(r["arm_id"] for r in bundle["resources"]))
            by_type = {r["resource_type"].lower(): r for r in bundle["resources"]}
            self.assertEqual(by_type[VM_KIND]["properties"]["configuredZones"], ["1"])
            self.assertEqual(
                by_type[DOMAIN_KIND]["properties"]["replicaConfiguration"]["population"],
                "terraform-initial-only",
            )
            self.assertEqual(by_type[DEFINITION_KIND]["arm_id"], DEFINITION)
        self.assertEqual(
            {r["resource_type"]: r["properties"] for r in raw["resources"]},
            {r["resource_type"]: r["properties"] for r in planned["resources"]},
        )

    def test_plan_composite_binding_conflicts_sensitive_unbound_and_provider_gaps(self):
        for index, value in ((2, DEFINITION + "|/"), (3, DOMAIN + "/replicaSets/fake")):
            plan = self.plan()
            plan["planned_values"]["root_module"]["resources"][index]["values"]["id"] = value
            with self.assertRaises(InputError):
                plan_source(
                    self.write("conflict.json", plan), scope=SCOPE, provider_version="4.50.0"
                )
        plan = self.plan()
        role = plan["planned_values"]["root_module"]["resources"][2]["values"]
        role["scope"] = SUB
        role["id"] = DEFINITION + "|" + SUB
        with self.assertRaisesRegex(InputError, "conflicts with its scope"):
            plan_source(
                self.write("foreign-role.json", plan), scope=SCOPE, provider_version="4.50.0"
            )
        plan = self.plan()
        rows = plan["planned_values"]["root_module"]["resources"]
        rows[2]["values"].pop("role_definition_resource_id")
        rows[3]["sensitive_values"] = {"initial_replica_set": True}
        bundle = plan_source(
            self.write("missing.json", plan), scope=SCOPE, provider_version="4.50.0"
        )
        self.assertIsNone(bundle["resources"][2]["arm_id"])
        self.assertIn("unknown", bundle["resources"][3]["properties"]["replicaConfiguration"])
        bundle = plan_source(
            self.write("provider.json", self.plan()), scope=SCOPE, provider_version="0"
        )
        self.assertTrue(all(r["state"] == "unknown" for r in bundle["resources"]))

    def test_arm_version_condition_scope_and_tenant_diagnostics_stay_unsupported(self):
        for kind in (DOMAIN_KIND, SET_KIND, DEFINITION_KIND):
            self.assertIn(kind, PLANNED_API_VERSIONS)
            self.assertNotIn(kind, API_VERSIONS)
        resources = [
            {
                "type": "Microsoft.AAD/domainServices",
                "apiVersion": "2022-12-01",
                "name": "authored",
                "location": "westeurope",
                "properties": {
                    "sku": "Enterprise",
                    "replicaSets": [{"location": "westeurope", "subnetId": SUBNET}],
                },
            },
            {
                "type": "Microsoft.AADIAM/diagnosticSettings",
                "apiVersion": "2017-04-01",
                "name": "not-subscription-scoped",
                "properties": {
                    "workspaceId": SENTINEL,
                    "logs": [{"category": "AuditLogs", "enabled": True}],
                },
            },
        ]
        bundle = arm_source(self.write("template.json", {"resources": resources}), scope=SCOPE)
        self.assertEqual(bundle["resources"][0]["state"], "known")
        self.assertEqual(bundle["resources"][1]["state"], "unknown")
        self.assertIsNone(bundle["resources"][1]["arm_id"])
        self.assertEqual(bundle["resources"][1]["properties"], {})
        self.assertFalse(bundle["inventory_complete"])
        self.assertIn(
            "tenant_directory_diagnostics_scope_unsupported", json.dumps(bundle["diagnostics"])
        )
        for change in ({"apiVersion": "2099-01-01"}, {"condition": "[parameters('undecided')]"}):
            resources[0].update(change)
            bundle = arm_source(
                self.write("unresolved.json", {"resources": resources}), scope=SCOPE
            )
            self.assertEqual(bundle["resources"][0]["state"], "unknown")
            self.assertEqual(bundle["resources"][0]["properties"], {})
        self.assertNotIn(SENTINEL, json.dumps(bundle))
        for display in ("B03.08", "B03.14", "B03.15"):
            self.assertEqual(review_context(self.control(display), self.bundle())["resources"], [])

    def test_blank_questions_separate_decisions_content_scope_and_expiry(self):
        bundle, catalog = self.bundle(), self.catalog()
        question = "identity-resilience-authored-not-registered"
        item = {
            "question": " ".join(
                q
                for row in self.matrix()["recommendations"]
                for q in row["evidence_requirements"]
                if q.startswith("Reviewer decision:")
            ),
            "controls": ["ALZ-" + guid for guid in GUIDS.values()],
        }
        original = copy.deepcopy(BANK)
        with patch.dict(BANK, {question: item}):
            response = prepare_interview(
                assess(bundle, catalog, at=AT, evidence_tiers=True), catalog, question, SCOPE
            )
            self.assertEqual(len(response["decisions"]), 8)
            self.assertTrue(all(d["outcome"] is None for d in response["decisions"]))
            for field in (
                "answer",
                "reviewer",
                "rationale",
                "evidence",
                "valid_from",
                "valid_until",
            ):
                self.assertIsNone(response[field])
            with self.assertRaises(InputError):
                compile_interview(response, catalog, at=AT)
            response.update(
                answer="Authored fixture: emergency operating and authentication decisions "
                "require separate evidence.",
                reviewer="Fixture reviewer",
                rationale="Eight explicit fixture decisions, not owner approval.",
                evidence="https://example.invalid/redacted-resilience",
                valid_from=AT,
                valid_until="2026-11-07T14:00:00Z",
            )
            for decision in response["decisions"]:
                decision["outcome"] = "fail"
            manual = compile_interview(response, catalog, at=AT)
            report = assess(bundle, catalog, at=AT, manual=manual, evidence_tiers=True)
            self.assertTrue(all(r["observed"]["outcome"] == "fail" for r in self.own(report)))
            for field, value in (
                ("scope", SUB),
                ("requirements_sha256", "0" * 64),
                ("valid_until", "2000-01-01T00:00:00Z"),
            ):
                changed = copy.deepcopy(response)
                changed[field] = value
                with self.assertRaises(InputError):
                    compile_interview(changed, catalog, at=AT)
            changed = copy.deepcopy(catalog)
            next(c for c in changed["controls"] if c["upstream_id"] == "B03.15")["rationale"] += (
                " Changed."
            )
            with self.assertRaises(InputError):
                compile_interview(response, changed, at=AT)
        self.assertEqual(BANK, original)

    def test_reports_session_manual_tiers_and_original_time_replay(self):
        bundle, catalog = self.bundle(), self.catalog()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        rows = self.own(report)
        expected = {"B03.09", "B03.10", "B03.11", "B03.13"}
        self.assertEqual(
            {r["upstream_id"] for r in rows if r["observed"]["evidence_tier"] == "signal"}, expected
        )
        self.assertEqual(
            next(r for r in rows if r["upstream_id"] == "B03.12")["observed"]["evidence_tier"],
            "manual",
        )
        for fmt in ("json", "markdown", "html", "csv", "sarif"):
            self.assertNotIn(SENTINEL, render(report, fmt))
        self.assertTrue(render_xlsx(report).startswith(b"PK"))
        self.assertEqual(
            ReviewSession(bundle, catalog, self.root / "session").state()["records"], []
        )
        projected = sanitize_evidence(bundle)
        self.assertEqual(projected["collected_at"], AT)
        for original, sanitized in zip(bundle["resources"], projected["resources"], strict=True):
            for path in (PATHS | {"configuredZones", "resourceLocation"}) & original[
                "properties"
            ].keys():
                self.assertEqual(
                    review_fact(original["properties"], path),
                    review_fact(sanitized["properties"], path),
                )
        for display in ("B03.09", "B03.11", "B03.13"):
            self.assertEqual(
                review_context(self.control(display), projected),
                review_context(self.control(display), bundle),
            )
        with self.assertRaisesRegex(InputError, "differs from a packaged artifact"):
            export_bundle(self.root / "not-accepted", bundle, catalog, at=AT, evidence_tiers=True)
        packaged = load_catalog()
        export_bundle(self.root / "accepted", bundle, packaged, at=AT, evidence_tiers=True)
        replayed = replay_bundle(self.root / "accepted")
        self.assertEqual(
            semantic(replayed), semantic(assess(bundle, packaged, at=AT, evidence_tiers=True))
        )
        self.assertEqual(replayed["evidence"][0]["collected_at"], AT)
        old = {c["upstream_guid"]: c for c in packaged["controls"]}
        for control in catalog["controls"]:
            if control["upstream_guid"] not in GUIDS.values():
                self.assertEqual(
                    control_digest(control), control_digest(old[control["upstream_guid"]])
                )

    def test_exceptions_and_confirmation_flags_never_manufacture_verified(self):
        catalog, bundle = self.catalog(), self.bundle()
        control = self.control("B03.15")
        for resource in bundle["resources"]:
            resource["properties"]["humanConfirmed"] = True
        exception = document(
            "exceptions",
            schema_version="1.1",
            entries=[
                {
                    "control_id": control["control_id"],
                    "control_sha256": control_digest(control),
                    "scope": SCOPE,
                    "rationale": "Authored exception, not authentication or operational proof.",
                    "reviewer": "Fixture reviewer",
                    "evidence": "https://example.invalid/redacted-exception",
                    "valid_from": AT,
                    "valid_until": "2026-11-07T14:00:00Z",
                    "disposition": "accepted",
                }
            ],
        )
        report = assess(bundle, catalog, at=AT, exceptions=exception, evidence_tiers=True)
        row = next(r for r in self.own(report) if r["upstream_id"] == "B03.15")
        self.assertEqual(row["observed"]["exception_disposition"], "accepted")
        self.assertNotEqual(row["observed"]["outcome"], "pass")
        self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")
        projected = sanitize_evidence(bundle)
        self.assertNotIn("humanConfirmed", json.dumps(projected))

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "existing Bicep compiler not supplied")
    def test_real_bicep_identity_resilience_without_restore(self):
        source = ROOT / "tests" / "fixtures" / "identity-resilience" / "main.bicep"
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("socket.socket.connect", side_effect=AssertionError("network forbidden")),
        ):
            copied = Path(temporary) / "main.bicep"
            copied.write_bytes(source.read_bytes())
            compiled = compile_bicep(copied, compiler=os.environ["BICEP_COMPILER"])
            bundle = arm_source(
                copied, scope=SCOPE, bicep=True, compiler=os.environ["BICEP_COMPILER"]
            )
        self.assertEqual(len(compiled["template"]["resources"]), 5)
        by_type = {r["resource_type"].lower(): r for r in bundle["resources"]}
        vms = [r for r in bundle["resources"] if r["resource_type"].lower() == VM_KIND]
        self.assertTrue(any(r["properties"]["configuredZones"] == ["1"] for r in vms))
        self.assertTrue(any(r["properties"].get("availabilitySetId") == AVAILABILITY for r in vms))
        self.assertEqual(by_type[SET_KIND]["properties"]["platformFaultDomainCount"], 2)
        self.assertEqual(by_type[DEFINITION_KIND]["properties"]["assignableScopeCount"], 1)
        self.assertEqual(
            by_type[DOMAIN_KIND]["properties"]["replicaConfiguration"]["replicaCount"], 2
        )
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
        self.assertFalse(source.with_suffix(".json").exists())


if __name__ == "__main__":
    unittest.main()
