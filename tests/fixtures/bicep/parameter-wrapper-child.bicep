targetScope = 'resourceGroup'

param secure bool

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'stofflinebinding'
  location: 'westeurope'
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: secure
  }
}
