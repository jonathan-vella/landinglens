resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'authored'
  location: 'westeurope'
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspace
  name: 'Heartbeat'
  properties: {
    plan: 'Analytics'
    retentionInDays: 730
    totalRetentionInDays: 4383
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'authored'
  location: 'westeurope'
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    minimumTlsVersion: 'TLS1_2'
  }
}

resource exportRule 'Microsoft.OperationalInsights/workspaces/dataExports@2020-08-01' = {
  parent: workspace
  name: 'authored'
  properties: {
    destination: {
      resourceId: storage.id
    }
    enable: true
    tableNames: [
      'Heartbeat'
    ]
  }
}

resource lock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: 'authored'
  scope: workspace
  properties: {
    level: 'CanNotDelete'
  }
}
