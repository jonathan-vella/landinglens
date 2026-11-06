targetScope = 'resourceGroup'

resource availability 'Microsoft.Compute/availabilitySets@2024-07-01' = {
  name: 'authored'
  location: 'westeurope'
  properties: {
    platformFaultDomainCount: 2
    platformUpdateDomainCount: 5
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: 'not-a-domain-controller'
  location: 'westeurope'
  zones: [
    '1'
  ]
  properties: {}
}

resource vmInSet 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: 'not-a-domain-controller-either'
  location: 'westeurope'
  properties: {
    availabilitySet: {
      id: availability.id
    }
  }
}

resource role 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: '11111111-1111-1111-1111-111111111111'
  properties: {
    type: 'CustomRole'
    roleName: 'authored-configuration-not-effective-access'
    assignableScopes: [
      '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/resilience'
    ]
    permissions: [
      {
        actions: [
          'Microsoft.Resources/subscriptions/resourceGroups/read'
        ]
      }
    ]
  }
}

resource domain 'Microsoft.AAD/domainServices@2022-12-01' = {
  name: 'authored'
  location: 'westeurope'
  properties: {
    sku: 'Enterprise'
    replicaSets: [
      {
        location: 'westeurope'
        subnetId: '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/resilience/providers/Microsoft.Network/virtualNetworks/primary/subnets/replica'
      }
      {
        location: 'northeurope'
        subnetId: '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/resilience/providers/Microsoft.Network/virtualNetworks/secondary/subnets/replica'
      }
    ]
  }
}
