targetScope = 'resourceGroup'

resource local 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'local'
  location: 'westeurope'
  properties: {
    addressSpace: {
      addressPrefixes: ['10.0.0.0/16']
    }
  }
}

resource remote 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'remote'
  location: 'westeurope'
  properties: {
    addressSpace: {
      addressPrefixes: ['10.1.0.0/16']
    }
  }
}

resource peering 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = {
  name: 'local/authored'
  properties: {
    allowVirtualNetworkAccess: true
    remoteVirtualNetwork: {
      id: remote.id
    }
  }
}

resource vault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: 'authored'
  location: 'westeurope'
  properties: {
    tenantId: '00000000-0000-0000-0000-000000000002'
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    accessPolicies: []
  }
}
