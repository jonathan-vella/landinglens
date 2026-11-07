targetScope = 'subscription'

type configurationType = {
  region: string
}

param configuration configurationType
param resourceGroupName string = 'rg-offline-binding'

resource group 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: resourceGroupName
}

module child './parameter-wrapper-child.bicep' = {
  name: 'offline-binding'
  scope: group
  params: {
    secure: empty(configuration.region) ? false : true
  }
}
