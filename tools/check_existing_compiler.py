"""Record exercised integration versus unavailable tooling; never acquire a compiler."""

import argparse
import json
import os
import shutil
import sys
import unittest
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--tests", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
compiler = os.environ.get("BICEP_COMPILER") or shutil.which("bicep")
record = {
    "status": "unavailable",
    "compiler": compiler,
    "exercised": False,
    "reason": "No existing compiler discovered; no installation or restoration attempted",
    "skipped": [],
}
success = True
if compiler:
    sys.path.insert(0, str(args.tests.resolve()))
    cases = [
        "test_bicep.BicepTests.test_actual_installed_compiler_local_success_and_unrestored_failure",
        "test_segmentation_batch.SegmentationBatchTests."
        "test_real_bicep_nsg_gateway_subnet_flow_without_restore",
        "test_routing_batch.RoutingBatchTests."
        "test_real_bicep_routing_peering_lb_macsec_connection_no_restore",
        "test_identity_batch.IdentityBatchTests."
        "test_real_bicep_storage_identity_role_context_without_restore",
        "test_protection_batch.ProtectionBatchTests."
        "test_real_bicep_protection_outbound_hybrid_no_restore",
        "test_security_batch.SecurityBatchTests."
        "test_real_bicep_security_configuration_without_restore",
        "test_expressroute_preparation.ExpressRoutePreparationTests."
        "test_real_bicep_expressroute_cost_capacity_fastpath_without_restore",
        "test_dns_batch.DnsBatchTests.test_real_bicep_dns_bastion_no_restore",
        "test_monitoring_preparation.MonitoringPreparationTests."
        "test_real_bicep_monitor_and_gateway_route_join_without_restore",
        "test_governance_preparation.GovernancePreparationTests."
        "test_real_bicep_governance_without_restore",
        "test_virtual_wan_preparation.VirtualWanPreparationTests."
        "test_real_bicep_virtual_wan_scoped_configuration_without_restore",
        "test_identity_resilience_preparation.IdentityResiliencePreparationTests."
        "test_real_bicep_identity_resilience_without_restore",
        "test_network_policy_preparation.NetworkPolicyPreparationTests."
        "test_real_bicep_policy_gateway_diagnostics_without_restore",
        "test_logging_preparation.LoggingPreparationTests."
        "test_real_bicep_logging_workspace_extensions_and_alerts_without_restore",
        "test_tenant_preparation.TenantPreparationTests."
        "test_real_bicep_tenant_configuration_without_restore",
        "test_policy_strategy_preparation.PolicyStrategyPreparationTests."
        "test_real_bicep_policy_strategy_without_restore",
        "test_hybrid_identity_preparation.HybridIdentityPreparationTests."
        "test_real_bicep_peering_and_vault_configuration_without_restore",
        "test_topology_preparation.TopologyPreparationTests."
        "test_real_bicep_vnet_routing_attachment_without_restore",
        "test_platform_health_preparation.PlatformHealthPreparationTests."
        "test_real_bicep_platform_health_configuration_without_restore",
        "test_sovereign_preparation.SovereignPreparationTests."
        "test_real_bicep_location_and_tag_configuration_without_restore",
    ]
    suite = unittest.defaultTestLoader.loadTestsFromNames(cases)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    exercised = result.wasSuccessful() and result.testsRun == len(cases) and not result.skipped
    success = result.wasSuccessful()
    record.update(
        status="exercised" if exercised else "skipped" if result.skipped else "failed",
        exercised=bool(exercised),
        reason="Existing compiler: local success and --no-restore missing-module failure"
        if exercised
        else "Integration did not exercise the compiler; inspect results",
        skipped=[reason for _, reason in result.skipped],
        integration_cases=cases,
    )
args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
print(json.dumps(record, indent=2))
raise SystemExit(0 if success else 1)
