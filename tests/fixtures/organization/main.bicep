targetScope = 'tenant'

resource anchor 'Microsoft.Management/managementGroups@2020-05-01' = {
  name: 'authored'
  properties: {}
}

resource child 'Microsoft.Management/managementGroups@2020-05-01' = {
  name: 'sandbox-platform-root-is-only-a-key'
  properties: {
    details: {
      parent: {
        id: '/providers/Microsoft.Management/managementGroups/authored'
      }
    }
  }
}

resource settings 'Microsoft.Management/managementGroups/settings@2020-05-01' = {
  name: 'authored/default'
  properties: {
    defaultManagementGroup: '/providers/Microsoft.Management/managementGroups/sandbox-platform-root-is-only-a-key'
    requireAuthorizationForGroupCreation: true
  }
}
