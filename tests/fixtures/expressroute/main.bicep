param portId string = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/expressroute/providers/Microsoft.Network/expressRoutePorts/direct'
param gatewayId string = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/expressroute/providers/Microsoft.Network/virtualNetworkGateways/gateway'
param circuitId string = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/expressroute/providers/Microsoft.Network/expressRouteCircuits/local'

resource port 'Microsoft.Network/ExpressRoutePorts@2024-05-01' = {
  name: 'direct'
  location: 'westeurope'
  properties: {
    bandwidthInGbps: 100
    billingType: 'MeteredData'
    encapsulation: 'QinQ'
    peeringLocation: 'Amsterdam'
  }
}

resource local 'Microsoft.Network/expressRouteCircuits@2024-05-01' = {
  name: 'local'
  location: 'westeurope'
  sku: {
    name: 'Local_UnlimitedData'
    tier: 'Local'
    family: 'UnlimitedData'
  }
  properties: {
    bandwidthInGbps: 10
    expressRoutePort: { id: portId }
    enableDirectPortRateLimit: true
  }
}

resource provider 'Microsoft.Network/expressRouteCircuits@2024-05-01' = {
  name: 'provider'
  location: 'westeurope'
  sku: {
    name: 'Standard_MeteredData'
    tier: 'Standard'
    family: 'MeteredData'
  }
  properties: {
    serviceProviderProperties: {
      serviceProviderName: 'Authored fixture provider'
      peeringLocation: 'Amsterdam'
      bandwidthInMbps: 500
    }
  }
}

resource connection 'Microsoft.Network/connections@2024-05-01' = {
  name: 'fastpath'
  location: 'westeurope'
  properties: {
    connectionType: 'ExpressRoute'
    virtualNetworkGateway1: { id: gatewayId }
    peer: { id: circuitId }
    expressRouteGatewayBypass: true
    enablePrivateLinkFastPath: true
  }
}
