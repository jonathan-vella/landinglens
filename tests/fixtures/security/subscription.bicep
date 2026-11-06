targetScope = 'subscription'

param workspaceId string
param storageAccountId string

resource posture 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'CloudPosture'
  properties: {
    pricingTier: 'Standard'
    enforce: 'True'
    extensions: [
      {
        name: 'AgentlessVmScanning'
        isEnabled: 'True'
      }
    ]
  }
}

resource servers 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'VirtualMachines'
  properties: {
    pricingTier: 'Standard'
    subPlan: 'P2'
  }
}

resource activity 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'activity'
  properties: {
    workspaceId: workspaceId
    storageAccountId: storageAccountId
    logs: [
      {
        category: 'Administrative'
        enabled: true
      }
      {
        category: 'Security'
        enabled: false
      }
    ]
  }
}
