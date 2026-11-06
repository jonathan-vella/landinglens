targetScope = 'resourceGroup'

param wanId string
param hubId string
param firewallId string
param vnetId string
param tableId string

resource wan 'Microsoft.Network/virtualWans@2024-05-01' = {
  name: 'wan'
  location: 'westeurope'
  properties: {
    type: 'Standard'
    allowBranchToBranchTraffic: true
  }
}

resource hub 'Microsoft.Network/virtualHubs@2024-05-01' = {
  name: 'hub'
  location: 'westeurope'
  properties: {
    virtualWan: {
      id: wanId
    }
    azureFirewall: {
      id: firewallId
    }
    addressPrefix: '10.12.0.0/22'
    allowBranchToBranchTraffic: true
    hubRoutingPreference: 'ASPath'
    virtualRouterAutoScaleConfiguration: {
      minCapacity: 2
    }
  }
}

resource firewall 'Microsoft.Network/azureFirewalls@2024-05-01' = {
  name: 'firewall'
  location: 'westeurope'
  properties: {
    sku: {
      name: 'AZFW_Hub'
      tier: 'Standard'
    }
    virtualHub: {
      id: hubId
    }
  }
}

resource table 'Microsoft.Network/virtualHubs/hubRouteTables@2024-05-01' = {
  name: 'hub/defaultRouteTable'
  properties: {
    labels: ['Default']
    routes: []
  }
}

resource connection 'Microsoft.Network/virtualHubs/hubVirtualNetworkConnections@2024-05-01' = {
  name: 'hub/connection'
  properties: {
    remoteVirtualNetwork: {
      id: vnetId
    }
    enableInternetSecurity: true
    routingConfiguration: {
      associatedRouteTable: {
        id: tableId
      }
      propagatedRouteTables: {
        labels: ['Default']
        ids: [
          {
            id: tableId
          }
        ]
      }
    }
  }
}

resource intent 'Microsoft.Network/virtualHubs/routingIntent@2024-05-01' = {
  name: 'hub/intent'
  properties: {
    routingPolicies: [
      {
        name: 'InternetTrafficPolicy'
        destinations: ['Internet']
        nextHop: firewallId
      }
    ]
  }
}
