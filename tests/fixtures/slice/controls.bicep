param secure bool = true
param dnsProxy bool = true
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'landinglenslogs'
  location: 'westeurope'
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: { supportsHttpsTrafficOnly: secure }
}
resource firewallPolicy 'Microsoft.Network/firewallPolicies@2024-05-01' = {
  name: 'landinglenspolicy'
  location: 'westeurope'
  properties: { dnsSettings: { enableProxy: dnsProxy } }
}
