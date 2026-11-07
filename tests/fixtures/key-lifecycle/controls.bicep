resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'authored'
  location: 'westeurope'
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    encryption: {
      keySource: 'Microsoft.Storage'
      requireInfrastructureEncryption: true
      services: {
        queue: {
          keyType: 'Account'
        }
        table: {
          keyType: 'Service'
        }
      }
    }
  }
}
