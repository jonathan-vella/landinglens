targetScope = 'resourceGroup'

param workspaceId string
param circuitId string
param actionGroupId string

resource table 'Microsoft.Network/routeTables@2024-05-01' = {
  name: 'propagation'
  location: 'westeurope'
  properties: {
    disableBgpRoutePropagation: false
  }
}

resource subnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  name: 'hub/GatewaySubnet'
  properties: {
    addressPrefix: '10.0.1.0/27'
    routeTable: {
      id: table.id
    }
  }
}

resource gateway 'Microsoft.Network/virtualNetworkGateways@2024-05-01' = {
  name: 'gateway'
  location: 'westeurope'
  properties: {
    gatewayType: 'ExpressRoute'
    ipConfigurations: [
      {
        name: 'configuration'
        properties: {
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', 'hub', 'GatewaySubnet')
          }
        }
      }
    ]
  }
}

resource monitor 'Microsoft.Network/networkWatchers/connectionMonitors@2024-05-01' = {
  name: 'watcher/monitor'
  location: 'westeurope'
  properties: {
    endpoints: [
      {
        name: 'from'
        type: 'AzureArcVM'
      }
      {
        name: 'to'
        type: 'AzureVM'
      }
    ]
    testConfigurations: [
      {
        name: 'tcp'
        protocol: 'Tcp'
        testFrequencySec: 60
        tcpConfiguration: {
          port: 443
        }
      }
    ]
    testGroups: [
      {
        name: 'hybrid'
        disable: false
        sources: ['from']
        destinations: ['to']
        testConfigurations: ['tcp']
      }
    ]
    outputs: [
      {
        type: 'Workspace'
        workspaceSettings: {
          workspaceResourceId: workspaceId
        }
      }
    ]
  }
}

resource alert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'availability'
  location: 'global'
  properties: {
    enabled: true
    severity: 2
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    scopes: [circuitId]
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'availability'
          criterionType: 'StaticThresholdCriterion'
          metricName: 'BgpAvailability'
          metricNamespace: 'Microsoft.Network/expressRouteCircuits'
          operator: 'LessThan'
          timeAggregation: 'Average'
          threshold: 1
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroupId
      }
    ]
  }
}

resource providerCircuit 'Microsoft.Network/expressRouteCircuits@2024-05-01' = {
  name: 'provider'
  location: 'westeurope'
  sku: {
    name: 'Standard_MeteredData'
    tier: 'Standard'
    family: 'MeteredData'
  }
  properties: {
    serviceProviderProperties: {
      serviceProviderName: 'reviewed-provider'
      peeringLocation: 'Amsterdam'
      bandwidthInMbps: 1000
    }
  }
}

resource port 'Microsoft.Network/expressRoutePorts@2024-05-01' = {
  name: 'direct'
  location: 'westeurope'
  properties: {
    peeringLocation: 'Amsterdam2'
    bandwidthInGbps: 100
    encapsulation: 'Dot1Q'
  }
}

resource directCircuit 'Microsoft.Network/expressRouteCircuits@2024-05-01' = {
  name: 'direct'
  location: 'westeurope'
  sku: {
    name: 'Standard_MeteredData'
    tier: 'Standard'
    family: 'MeteredData'
  }
  properties: {
    expressRoutePort: {
      id: port.id
    }
    bandwidthInGbps: 10
  }
}

resource firstConnection 'Microsoft.Network/connections@2024-05-01' = {
  name: 'first'
  location: 'westeurope'
  properties: {
    connectionType: 'ExpressRoute'
    virtualNetworkGateway1: {
      id: gateway.id
    }
    peer: {
      id: providerCircuit.id
    }
  }
}

resource secondConnection 'Microsoft.Network/connections@2024-05-01' = {
  name: 'second'
  location: 'westeurope'
  properties: {
    connectionType: 'ExpressRoute'
    virtualNetworkGateway1: {
      id: gateway.id
    }
    peer: {
      id: directCircuit.id
    }
  }
}
