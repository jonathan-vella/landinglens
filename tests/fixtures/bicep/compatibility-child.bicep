param fallbackName string
param name string = fallbackName
param prefix string
param optionalTags object?

resource network 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: name
  location: 'westeurope'
  properties: {
    addressSpace: {
      addressPrefixes: [prefix]
    }
  }
  tags: optionalTags
}

output name string = network.name
output resourceId string = network.id
