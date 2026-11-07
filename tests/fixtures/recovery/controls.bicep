resource machine 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: 'authored'
  location: 'westeurope'
  properties: {}
}

resource guest 'Microsoft.GuestConfiguration/guestConfigurationAssignments@2024-04-05' = {
  name: 'authored'
  scope: machine
  location: 'westeurope'
  properties: {
    guestConfiguration: {
      assignmentType: 'Audit'
    }
  }
}

resource extension 'Microsoft.Compute/virtualMachines/extensions@2024-07-01' = {
  parent: machine
  name: 'AzurePolicyforLinux'
  location: 'westeurope'
  properties: {
    publisher: 'Microsoft.GuestConfiguration'
    type: 'ConfigurationForLinux'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: false
  }
}

resource vault 'Microsoft.DataProtection/backupVaults@2024-04-01' = {
  name: 'authored'
  location: 'westeurope'
  properties: {
    storageSettings: [
      {
        datastoreType: 'VaultStore'
        type: 'ZoneRedundant'
      }
    ]
  }
}

resource failover 'Microsoft.Sql/servers/failoverGroups@2023-08-01' = {
  name: 'primary/authored'
  properties: {
    readWriteEndpoint: {
      failoverPolicy: 'Manual'
    }
    partnerServers: [
      {
        id: resourceId('Microsoft.Sql/servers', 'secondary')
      }
    ]
    databases: [
      resourceId('Microsoft.Sql/servers/databases', 'primary', 'authored')
    ]
  }
}

resource profile 'Microsoft.Cdn/profiles@2024-02-01' = {
  name: 'authored'
  location: 'global'
  sku: {
    name: 'Premium_AzureFrontDoor'
  }
  properties: {}
}

resource diagnostic 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: profile
  name: 'authored'
  properties: {
    workspaceId: resourceId('Microsoft.OperationalInsights/workspaces', 'authored')
    logs: [
      {
        category: 'FrontDoorWebApplicationFirewallLog'
        enabled: true
      }
    ]
  }
}
