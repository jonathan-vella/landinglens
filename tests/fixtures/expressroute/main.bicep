param portId string = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/expressroute/providers/Microsoft.Network/expressRoutePorts/direct'
param gatewayId string = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/expressroute/providers/Microsoft.Network/virtualNetworkGateways/gateway'
param circuitId string = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/expressroute/providers/Microsoft.Network/expressRouteCircuits/local'
param publicIpId string = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/expressroute/providers/Microsoft.Network/publicIPAddresses/gateway'
param subnetId string = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/expressroute/providers/Microsoft.Network/virtualNetworks/hub/subnets/GatewaySubnet'

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

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: 'gateway'
  location: 'eastus'
  sku: { name: 'Standard' }
  zones: ['1', '2', '3']
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource gateway 'Microsoft.Network/virtualNetworkGateways@2024-05-01' = {
  name: 'gateway'
  location: 'eastus'
  properties: {
    gatewayType: 'ExpressRoute'
    sku: {
      name: 'ErGwScale'
      tier: 'ErGwScale'
    }
    autoScaleConfiguration: { bounds: { min: 10, max: 10 } }
    ipConfigurations: [
      {
        name: 'gateway'
        properties: {
          publicIPAddress: { id: publicIpId }
          subnet: { id: subnetId }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
  }
}
