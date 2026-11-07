targetScope = 'resourceGroup'

param connectivitySubscriptionId string
param useSwedenRemoteGateway bool = true
param useGermanyRemoteGateway bool = true
param allowSwedenPeeringAccess bool = true

resource swedenNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: 'nsg-spoke-swedencentral'
  location: 'swedencentral'
  properties: {
    securityRules: []
  }
}

resource germanyNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: 'nsg-spoke-germanywestcentral'
  location: 'germanywestcentral'
  properties: {
    securityRules: []
  }
}

resource swedenRouteTable 'Microsoft.Network/routeTables@2024-07-01' = {
  name: 'rt-spoke-swedencentral'
  location: 'swedencentral'
  properties: {
    disableBgpRoutePropagation: false
    routes: [
      {
        name: 'default-via-regional-firewall'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: '10.10.0.4'
        }
      }
    ]
  }
}

resource germanyRouteTable 'Microsoft.Network/routeTables@2024-07-01' = {
  name: 'rt-spoke-germanywestcentral'
  location: 'germanywestcentral'
  properties: {
    disableBgpRoutePropagation: false
    routes: [
      {
        name: 'default-via-regional-firewall'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: '10.20.0.4'
        }
      }
    ]
  }
}

resource swedenSpoke 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'vnet-spoke-swedencentral'
  location: 'swedencentral'
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.11.0.0/24'
      ]
    }
  }
}

resource germanySpoke 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'vnet-spoke-germanywestcentral'
  location: 'germanywestcentral'
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.21.0.0/24'
      ]
    }
  }
}

resource swedenSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  parent: swedenSpoke
  name: 'workload'
  properties: {
    addressPrefix: '10.11.0.0/24'
    networkSecurityGroup: {
      id: swedenNsg.id
    }
    routeTable: {
      id: swedenRouteTable.id
    }
  }
}

resource germanySubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  parent: germanySpoke
  name: 'workload'
  properties: {
    addressPrefix: '10.21.0.0/24'
    networkSecurityGroup: {
      id: germanyNsg.id
    }
    routeTable: {
      id: germanyRouteTable.id
    }
  }
}

resource swedenSpokeToHub 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-01-01' = {
  parent: swedenSpoke
  name: 'to-hub-swedencentral'
  properties: {
    remoteVirtualNetwork: {
      id: '/subscriptions/${connectivitySubscriptionId}/resourceGroups/rg-alz-hub-swedencentral/providers/Microsoft.Network/virtualNetworks/vnet-hub-swedencentral'
    }
    allowVirtualNetworkAccess: allowSwedenPeeringAccess
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: useSwedenRemoteGateway
  }
}

resource germanySpokeToHub 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-01-01' = {
  parent: germanySpoke
  name: 'to-hub-germanywestcentral'
  properties: {
    remoteVirtualNetwork: {
      id: '/subscriptions/${connectivitySubscriptionId}/resourceGroups/rg-alz-hub-germanywestcentral/providers/Microsoft.Network/virtualNetworks/vnet-hub-germanywestcentral'
    }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: useGermanyRemoteGateway
  }
}
