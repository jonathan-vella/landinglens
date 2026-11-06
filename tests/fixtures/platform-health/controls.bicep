resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'authoredlogs'
  location: 'westeurope'
  kind: 'StorageV2'
  sku: {
    name: 'Standard_ZRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
  }
}

resource actions 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: 'authored-actions'
  location: 'global'
  properties: {
    enabled: true
    groupShortName: 'fixture'
    emailReceivers: []
    smsReceivers: []
    voiceReceivers: []
    azureAppPushReceivers: []
    armRoleReceivers: []
    automationRunbookReceivers: []
    azureFunctionReceivers: []
    eventHubReceivers: []
    itsmReceivers: []
    logicAppReceivers: []
    webhookReceivers: []
  }
}

resource service 'Microsoft.Insights/activityLogAlerts@2020-10-01' = {
  name: 'authored-service-health'
  location: 'global'
  properties: {
    enabled: true
    scopes: [resourceGroup().id]
    condition: {
      allOf: [{
        field: 'category'
        equals: 'ServiceHealth'
      }]
    }
    actions: {
      actionGroups: [{
        actionGroupId: actions.id
      }]
    }
  }
}

resource health 'Microsoft.Insights/activityLogAlerts@2020-10-01' = {
  name: 'authored-resource-health'
  location: 'global'
  properties: {
    enabled: false
    scopes: [storage.id]
    condition: {
      allOf: [{
        field: 'category'
        equals: 'ResourceHealth'
      }]
    }
    actions: {
      actionGroups: [{
        actionGroupId: actions.id
      }]
    }
  }
}

resource metric 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'authored-operational'
  location: 'global'
  properties: {
    enabled: true
    severity: 3
    scopes: [storage.id]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [{
        name: 'authored'
        criterionType: 'StaticThresholdCriterion'
        metricNamespace: 'Microsoft.Storage/storageAccounts'
        metricName: 'Transactions'
        operator: 'GreaterThan'
        timeAggregation: 'Total'
        threshold: 1
      }]
    }
    actions: [{
      actionGroupId: actions.id
    }]
  }
}
