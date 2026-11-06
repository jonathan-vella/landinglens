resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'authored-vnet'
  location: 'westeurope'
  properties: {
    addressSpace: { addressPrefixes: ['10.0.0.0/16'] }
  }
}

resource subnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  name: 'authored-vnet/RouteServerSubnet'
  properties: { addressPrefix: '10.0.0.0/26' }
}

resource routing 'Microsoft.Network/virtualHubs@2024-05-01' = {
  name: 'authored-routing'
  location: 'westeurope'
  properties: {
    sku: 'Standard'
    allowBranchToBranchTraffic: true
    hubRoutingPreference: 'ExpressRoute'
  }
}

resource attachment 'Microsoft.Network/virtualHubs/ipConfigurations@2024-05-01' = {
  name: 'authored-routing/authored-attachment'
  properties: {
    subnet: {
      id: resourceId('Microsoft.Network/virtualNetworks/subnets', 'authored-vnet', 'RouteServerSubnet')
    }
  }
}
