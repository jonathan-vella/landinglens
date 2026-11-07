targetScope = 'subscription'

param workloadSubscriptionId string
param workloadResourceGroupName string = 'rg-alz-workloads'
param allowSwedenPeeringAccess bool = true
param swedenLocalGatewayIp string = '203.0.113.10'
param germanyLocalGatewayIp string = '203.0.113.20'
param swedenOnPremisesPrefix string = '192.168.10.0/24'
param germanyOnPremisesPrefix string = '192.168.20.0/24'
@secure()
param swedenVpnSharedKey string
@secure()
param germanyVpnSharedKey string

module swedenHubConfiguration './region.bicep' = {
  name: 'alz-hub-swedencentral-configuration'
  scope: resourceGroup('rg-alz-hub-swedencentral')
  params: {
    hubVirtualNetworkName: 'vnet-hub-swedencentral'
    hubLocation: 'swedencentral'
    remoteSpokeResourceId: '/subscriptions/${workloadSubscriptionId}/resourceGroups/${workloadResourceGroupName}/providers/Microsoft.Network/virtualNetworks/vnet-spoke-swedencentral'
    peeringName: 'to-spoke-swedencentral'
    allowVirtualNetworkAccess: allowSwedenPeeringAccess
    gatewayName: 'vgw-alz-swedencentral'
    localGatewayName: 'lng-fictional-swedencentral'
    localGatewayIp: swedenLocalGatewayIp
    onPremisesPrefix: swedenOnPremisesPrefix
    connectionName: 'conn-fictional-swedencentral'
    sharedKey: swedenVpnSharedKey
  }
}

module germanyHubConfiguration './region.bicep' = {
  name: 'alz-hub-germanywestcentral-configuration'
  scope: resourceGroup('rg-alz-hub-germanywestcentral')
  params: {
    hubVirtualNetworkName: 'vnet-hub-germanywestcentral'
    hubLocation: 'germanywestcentral'
    remoteSpokeResourceId: '/subscriptions/${workloadSubscriptionId}/resourceGroups/${workloadResourceGroupName}/providers/Microsoft.Network/virtualNetworks/vnet-spoke-germanywestcentral'
    peeringName: 'to-spoke-germanywestcentral'
    allowVirtualNetworkAccess: true
    gatewayName: 'vgw-alz-germanywestcentral'
    localGatewayName: 'lng-fictional-germanywestcentral'
    localGatewayIp: germanyLocalGatewayIp
    onPremisesPrefix: germanyOnPremisesPrefix
    connectionName: 'conn-fictional-germanywestcentral'
    sharedKey: germanyVpnSharedKey
  }
}
