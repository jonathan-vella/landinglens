targetScope = 'tenant'

param managementSubscriptionId string = '00000000-0000-0000-0000-000000000001'
param connectivitySubscriptionId string = '00000000-0000-0000-0000-000000000002'
param workloadSubscriptionId string = '00000000-0000-0000-0000-000000000005'
param identitySubscriptionId string = '00000000-0000-0000-0000-000000000003'
param securitySubscriptionId string = '00000000-0000-0000-0000-000000000004'

resource alzRoot 'Microsoft.Management/managementGroups@2020-05-01' = {
  name: 'fictional-alz'
  properties: {
    details: {
      parent: {
        id: '/providers/Microsoft.Management/managementGroups/fictional-tenant-root'
      }
    }
  }
}

resource platform 'Microsoft.Management/managementGroups@2020-05-01' = {
  name: 'platform'
  properties: {
    details: {
      parent: {
        id: alzRoot.id
      }
    }
  }
}

resource landingZones 'Microsoft.Management/managementGroups@2020-05-01' = {
  name: 'landing-zones'
  properties: {
    details: {
      parent: {
        id: alzRoot.id
      }
    }
  }
}

resource sandbox 'Microsoft.Management/managementGroups@2020-05-01' = {
  name: 'sandbox'
  properties: {
    details: {
      parent: {
        id: alzRoot.id
      }
    }
  }
}

resource decommissioned 'Microsoft.Management/managementGroups@2020-05-01' = {
  name: 'decommissioned'
  properties: {
    details: {
      parent: {
        id: alzRoot.id
      }
    }
  }
}

resource management 'Microsoft.Management/managementGroups@2020-05-01' = {
  name: 'management'
  properties: {
    details: {
      parent: {
        id: platform.id
      }
    }
  }
}

resource connectivity 'Microsoft.Management/managementGroups@2020-05-01' = {
  name: 'connectivity'
  properties: {
    details: {
      parent: {
        id: platform.id
      }
    }
  }
}

resource identity 'Microsoft.Management/managementGroups@2020-05-01' = {
  name: 'identity'
  properties: {
    details: {
      parent: {
        id: platform.id
      }
    }
  }
}

resource security 'Microsoft.Management/managementGroups@2020-05-01' = {
  name: 'security'
  properties: {
    details: {
      parent: {
        id: platform.id
      }
    }
  }
}

resource managementSubscription 'Microsoft.Management/managementGroups/subscriptions@2020-05-01' = {
  parent: management
  name: managementSubscriptionId
}

resource connectivitySubscription 'Microsoft.Management/managementGroups/subscriptions@2020-05-01' = {
  parent: connectivity
  name: connectivitySubscriptionId
}

resource identitySubscription 'Microsoft.Management/managementGroups/subscriptions@2020-05-01' = {
  parent: identity
  name: identitySubscriptionId
}

resource securitySubscription 'Microsoft.Management/managementGroups/subscriptions@2020-05-01' = {
  parent: security
  name: securitySubscriptionId
}

resource workloadSubscription 'Microsoft.Management/managementGroups/subscriptions@2020-05-01' = {
  parent: landingZones
  name: workloadSubscriptionId
}

module workloadPolicies './policies.bicep' = {
  name: 'alz-workload-policies'
  scope: managementGroup(landingZones.name)
  params: {
    deployNetworkPolicy: true
    deployTagPolicy: false
  }
}

module platformPolicies './policies.bicep' = {
  name: 'alz-platform-policies'
  scope: managementGroup(platform.name)
  params: {
    deployNetworkPolicy: false
    deployTagPolicy: true
  }
}
