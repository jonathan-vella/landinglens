targetScope = 'subscription'

@allowed([
  'Alert'
  'Deny'
  'Off'
])
param firewallThreatIntelMode string = 'Deny'
param allowSwedenPeeringAccess bool = true
param workloadSubscriptionId string = '00000000-0000-0000-0000-000000000005'
param workloadResourceGroupName string = 'rg-alz-workloads'
@secure()
param swedenVpnSharedKey string
@secure()
param germanyVpnSharedKey string

var hubNetworks = [
  {
    name: 'vnet-hub-swedencentral'
    location: 'swedencentral'
    addressPrefixes: [
      '10.10.0.0/16'
    ]
    azureFirewallSettings: {
      deployAzureFirewall: true
      azureSkuTier: 'Premium'
      threatIntelMode: firewallThreatIntelMode
      azureFirewallName: 'afw-alz-swedencentral'
      zones: [
        1
        2
        3
      ]
    }
    privateDnsSettings: {
      deployPrivateDnsZones: false
      deployDnsPrivateResolver: false
    }
    ddosProtectionPlanSettings: {
      deployDdosProtectionPlan: false
    }
    deployPeering: true
    peeringSettings: [
      {
        remoteVirtualNetworkName: 'vnet-hub-germanywestcentral'
        allowVirtualNetworkAccess: true
        allowForwardedTraffic: true
      }
    ]
    subnets: [
      {
        name: 'AzureFirewallSubnet'
        addressPrefix: '10.10.0.0/26'
      }
      {
        name: 'GatewaySubnet'
        addressPrefix: '10.10.1.0/27'
      }
    ]
    vpnGatewaySettings: {
      deployVpnGateway: true
      name: 'vgw-alz-swedencentral'
      skuName: 'VpnGw2AZ'
      vpnMode: 'activePassiveNoBgp'
      vpnType: 'RouteBased'
      vpnGatewayGeneration: 'Generation2'
      publicIpZones: [
        1
        2
        3
      ]
    }
    bastionHostSettings: {
      deployBastion: false
    }
  }
  {
    name: 'vnet-hub-germanywestcentral'
    location: 'germanywestcentral'
    addressPrefixes: [
      '10.20.0.0/16'
    ]
    azureFirewallSettings: {
      deployAzureFirewall: true
      azureSkuTier: 'Premium'
      threatIntelMode: firewallThreatIntelMode
      azureFirewallName: 'afw-alz-germanywestcentral'
      zones: [
        1
        2
        3
      ]
    }
    privateDnsSettings: {
      deployPrivateDnsZones: false
      deployDnsPrivateResolver: false
    }
    ddosProtectionPlanSettings: {
      deployDdosProtectionPlan: false
    }
    deployPeering: true
    peeringSettings: [
      {
        remoteVirtualNetworkName: 'vnet-hub-swedencentral'
        allowVirtualNetworkAccess: true
        allowForwardedTraffic: true
      }
    ]
    subnets: [
      {
        name: 'AzureFirewallSubnet'
        addressPrefix: '10.20.0.0/26'
      }
      {
        name: 'GatewaySubnet'
        addressPrefix: '10.20.1.0/27'
      }
    ]
    vpnGatewaySettings: {
      deployVpnGateway: true
      name: 'vgw-alz-germanywestcentral'
      skuName: 'VpnGw2AZ'
      vpnMode: 'activePassiveNoBgp'
      vpnType: 'RouteBased'
      vpnGatewayGeneration: 'Generation2'
      publicIpZones: [
        1
        2
        3
      ]
    }
    bastionHostSettings: {
      deployBastion: false
    }
  }
]

module acceleratorHubs '../upstream/templates/networking/hubnetworking/main.bicep' = {
  name: 'alz-accelerator-hubs'
  params: {
    parHubNetworkingResourceGroupNamePrefix: 'rg-alz-hub'
    parDnsResourceGroupNamePrefix: 'rg-alz-dns'
    parDnsPrivateResolverResourceGroupNamePrefix: 'rg-alz-dns-resolver'
    hubNetworks: hubNetworks
    parLocations: [
      'swedencentral'
      'germanywestcentral'
    ]
    parTags: {
      environment: 'fictional'
      purpose: 'landinglens-offline-assessment'
    }
    parEnableTelemetry: false
    parGlobalResourceLock: {
      kind: 'None'
      notes: 'Offline simulation only.'
    }
  }
}

module regionalConnectivity './hub-spoke.bicep' = {
  name: 'alz-regional-hybrid-connectivity'
  params: {
    workloadSubscriptionId: workloadSubscriptionId
    workloadResourceGroupName: workloadResourceGroupName
    allowSwedenPeeringAccess: allowSwedenPeeringAccess
    swedenVpnSharedKey: swedenVpnSharedKey
    germanyVpnSharedKey: germanyVpnSharedKey
  }
}
