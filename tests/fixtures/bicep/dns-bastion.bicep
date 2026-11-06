resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'dns-network'
  location: 'westeurope'
  properties: {
    addressSpace: { addressPrefixes: ['10.0.0.0/16'] }
    dhcpOptions: { dnsServers: [] }
    encryption: { enabled: false, enforcement: 'AllowUnencrypted' }
  }
}
resource inboundSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  parent: vnet
  name: 'inbound'
  properties: {
    addressPrefix: '10.0.0.0/28'
    delegations: [{
      name: 'resolver'
      properties: { serviceName: 'Microsoft.Network/dnsResolvers' }
    }]
  }
}
resource outboundSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  parent: vnet
  name: 'outbound'
  properties: {
    addressPrefix: '10.0.0.16/28'
    delegations: [{
      name: 'resolver'
      properties: { serviceName: 'Microsoft.Network/dnsResolvers' }
    }]
  }
}
resource bastionSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  parent: vnet
  name: 'AzureBastionSubnet'
  properties: { addressPrefix: '10.0.1.0/26' }
}
resource zone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'fixture.example.invalid'
  location: 'global'
  properties: {}
}
resource zoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: zone
  name: 'network'
  location: 'global'
  properties: {
    registrationEnabled: true
    resolutionPolicy: 'Default'
    virtualNetwork: { id: vnet.id }
  }
}
resource resolver 'Microsoft.Network/dnsResolvers@2022-07-01' = {
  name: 'resolver'
  location: 'westeurope'
  properties: { virtualNetwork: { id: vnet.id } }
}
resource inbound 'Microsoft.Network/dnsResolvers/inboundEndpoints@2022-07-01' = {
  parent: resolver
  name: 'inbound'
  location: 'westeurope'
  properties: {
    ipConfigurations: [{
      subnet: { id: inboundSubnet.id }
      privateIpAllocationMethod: 'Dynamic'
    }]
  }
}
resource outbound 'Microsoft.Network/dnsResolvers/outboundEndpoints@2022-07-01' = {
  parent: resolver
  name: 'outbound'
  location: 'westeurope'
  properties: { subnet: { id: outboundSubnet.id } }
}
resource ruleset 'Microsoft.Network/dnsForwardingRulesets@2022-07-01' = {
  name: 'ruleset'
  location: 'westeurope'
  properties: { dnsResolverOutboundEndpoints: [{ id: outbound.id }] }
}
resource rule 'Microsoft.Network/dnsForwardingRulesets/forwardingRules@2022-07-01' = {
  parent: ruleset
  name: 'fixture'
  properties: {
    domainName: 'private-sensitive-record.example.invalid.'
    forwardingRuleState: 'Enabled'
    targetDnsServers: [{ ipAddress: '10.23.45.67', port: 53 }]
  }
}
resource rulesetLink 'Microsoft.Network/dnsForwardingRulesets/virtualNetworkLinks@2022-07-01' = {
  parent: ruleset
  name: 'network'
  properties: { virtualNetwork: { id: vnet.id } }
}
resource ip 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: 'bastion'
  location: 'westeurope'
  sku: { name: 'Standard', tier: 'Regional' }
  zones: ['1', '2', '3']
  properties: { publicIPAllocationMethod: 'Static', publicIPAddressVersion: 'IPv4' }
}
resource bastion 'Microsoft.Network/bastionHosts@2024-05-01' = {
  name: 'bastion'
  location: 'westeurope'
  sku: { name: 'Premium' }
  properties: {
    scaleUnits: 2
    enablePrivateOnlyBastion: false
    enableSessionRecording: true
    enableShareableLink: false
    ipConfigurations: [{
      name: 'primary'
      properties: {
        subnet: { id: bastionSubnet.id }
        publicIPAddress: { id: ip.id }
      }
    }]
  }
}
