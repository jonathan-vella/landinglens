param location string = 'westeurope'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'central-logs'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Disabled'
  }
}

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  name: 'default'
  scope: workspace
  properties: { customerManagedKey: false }
}

resource topic 'Microsoft.EventGrid/topics@2022-06-15' = {
  name: 'authored-topic'
  location: location
  properties: {
    inputSchema: 'EventGridSchema'
    publicNetworkAccess: 'Enabled'
  }
}

resource diagnostic 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'central-routing'
  scope: topic
  properties: {
    workspaceId: workspace.id
    logs: [
      { categoryGroup: 'allLogs', enabled: true }
    ]
    logAnalyticsDestinationType: 'Dedicated'
  }
}

resource queryAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: 'authored-log-alert'
  location: location
  kind: 'LogAlert'
  properties: {
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    scopes: [workspace.id]
    severity: 3
    criteria: {
      allOf: [
        {
          query: 'print authored_fixture = 1'
          operator: 'GreaterThan'
          threshold: 0
          timeAggregation: 'Count'
        }
      ]
    }
    actions: { actionGroups: [] }
  }
}

resource metricAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'authored-topic-metric'
  location: 'global'
  properties: {
    enabled: true
    severity: 3
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    scopes: [topic.id]
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'authored-dead-letter'
          criterionType: 'StaticThresholdCriterion'
          metricNamespace: 'Microsoft.EventGrid/topics'
          metricName: 'DeadLetteredCount'
          operator: 'GreaterThan'
          threshold: 0
          timeAggregation: 'Total'
        }
      ]
    }
    actions: []
  }
}
