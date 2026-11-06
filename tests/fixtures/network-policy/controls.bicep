targetScope = 'resourceGroup'

param workspaceId string
param actionGroupId string
param virtualHubId string

resource partner 'Microsoft.Network/securityPartnerProviders@2024-05-01' = {
  name: 'partner'
  location: 'westeurope'
  properties: {
    securityProviderName: 'ZScaler'
    virtualHub: { id: virtualHubId }
  }
}

resource base 'Microsoft.Network/firewallPolicies@2024-05-01' = {
  name: 'base'
  location: 'westeurope'
  properties: {
    dnsSettings: { enableProxy: false }
  }
}

resource child 'Microsoft.Network/firewallPolicies@2024-05-01' = {
  name: 'child'
  location: 'westeurope'
  properties: {
    basePolicy: { id: base.id }
    dnsSettings: { enableProxy: true }
  }
}

resource firewall 'Microsoft.Network/azureFirewalls@2024-05-01' = {
  name: 'firewall'
  location: 'westeurope'
  properties: {
    sku: { name: 'AZFW_VNet', tier: 'Standard' }
    firewallPolicy: { id: child.id }
  }
}

resource group 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2024-05-01' = {
  parent: child
  name: 'egress'
  properties: {
    priority: 200
    ruleCollections: [
      {
        name: 'network'
        priority: 200
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        action: { type: 'Allow' }
        rules: [
          {
            name: 'authored'
            ruleType: 'NetworkRule'
            ipProtocols: ['TCP', 'UDP']
            sourceAddresses: ['10.0.0.0/24']
            destinationFqdns: ['authored.example.invalid']
            destinationPorts: ['123']
          }
        ]
      }
    ]
  }
}

resource gateway 'Microsoft.Network/virtualNetworkGateways@2024-05-01' = {
  name: 'gateway'
  location: 'westeurope'
  properties: {
    gatewayType: 'ExpressRoute'
    allowRemoteVnetTraffic: false
    allowVirtualWanTraffic: true
  }
}

resource diagnostic 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: gateway
  name: 'logs'
  properties: {
    workspaceId: workspaceId
    logs: [
      { category: 'GatewayDiagnosticLog', enabled: true }
    ]
  }
}

resource alert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'gateway-cpu'
  location: 'global'
  properties: {
    enabled: true
    severity: 2
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    scopes: [gateway.id]
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'authored-cpu'
          criterionType: 'StaticThresholdCriterion'
          metricName: 'ExpressRouteGatewayCpuUtilization'
          metricNamespace: 'Microsoft.Network/virtualNetworkGateways'
          operator: 'GreaterThan'
          timeAggregation: 'Average'
          threshold: 73
        }
      ]
    }
    actions: [{ actionGroupId: actionGroupId }]
  }
}
