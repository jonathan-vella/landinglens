targetScope = 'subscription'

param logRetentionDays int = 90

module acceleratorManagementLogging '../upstream/templates/core/logging/main.bicep' = {
  name: 'alz-accelerator-management-logging'
  params: {
    parMgmtLoggingResourceGroup: 'rg-alz-management'
    parAutomationAccountName: 'aa-alz-management'
    parDeployAutomationAccount: false
    parLogAnalyticsWorkspaceName: 'law-alz-central'
    parLogAnalyticsWorkspaceLocation: 'swedencentral'
    parLogAnalyticsWorkspaceLogRetentionInDays: logRetentionDays
    parLogAnalyticsWorkspaceSolutions: []
    parUserAssignedIdentityName: 'id-alz-monitoring'
    parDataCollectionRuleVMInsightsName: 'dcr-alz-vminsights'
    parDataCollectionRuleChangeTrackingName: 'dcr-alz-changetracking'
    parDataCollectionRuleMDFCSQLName: 'dcr-alz-mdfc-sql'
    parLocations: [
      'swedencentral'
    ]
    parTags: {
      environment: 'fictional'
      purpose: 'landinglens-offline-assessment'
    }
    parEnableTelemetry: false
    parGlobalResourceLock: {
      kind: 'None'
      notes: 'Offline simulation only.'
    }
  }
}
