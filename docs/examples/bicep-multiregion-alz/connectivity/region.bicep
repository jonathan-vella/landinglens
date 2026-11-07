targetScope = 'resourceGroup'

param hubVirtualNetworkName string
param hubLocation string
param remoteSpokeResourceId string
param peeringName string
param allowVirtualNetworkAccess bool
param gatewayName string
param localGatewayName string
param localGatewayIp string
param onPremisesPrefix string
param connectionName string
@secure()
param sharedKey string

resource hub 'Microsoft.Network/virtualNetworks@2024-05-01' existing = {
  name: hubVirtualNetworkName
}

resource hubToSpoke 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-01-01' = {
  parent: hub
  name: peeringName
  properties: {
    remoteVirtualNetwork: {
      id: remoteSpokeResourceId
    }
    allowVirtualNetworkAccess: allowVirtualNetworkAccess
    allowForwardedTraffic: true
    allowGatewayTransit: true
    useRemoteGateways: false
  }
}

resource localNetworkGateway 'Microsoft.Network/localNetworkGateways@2024-05-01' = {
  name: localGatewayName
  location: hubLocation
  properties: {
    gatewayIpAddress: localGatewayIp
    localNetworkAddressSpace: {
      addressPrefixes: [
        onPremisesPrefix
      ]
    }
  }
}

resource vpnConnection 'Microsoft.Network/connections@2024-05-01' = {
  name: connectionName
  location: hubLocation
  properties: {
    connectionType: 'IPsec'
    connectionProtocol: 'IKEv2'
    enableBgp: false
    virtualNetworkGateway1: {
      id: resourceId('Microsoft.Network/virtualNetworkGateways', gatewayName)
      properties: {}
    }
    localNetworkGateway2: {
      id: localNetworkGateway.id
      properties: {}
    }
    sharedKey: sharedKey
  }
}
