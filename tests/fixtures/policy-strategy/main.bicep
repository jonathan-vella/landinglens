targetScope = 'subscription'

resource definition 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: 'authored-policy'
  properties: {
    policyType: 'Custom'
    mode: 'All'
    version: '1.2.3'
    policyRule: {
      if: {
        field: 'type'
        equals: 'Microsoft.Storage/storageAccounts'
      }
      then: {
        effect: 'audit'
      }
    }
  }
}

resource initiative 'Microsoft.Authorization/policySetDefinitions@2023-04-01' = {
  name: 'authored-initiative'
  properties: {
    policyType: 'Custom'
    version: '1.2.3'
    policyDefinitions: [
      {
        policyDefinitionId: definition.id
        policyDefinitionReferenceId: 'authored-member'
        definitionVersion: '1.2.3'
      }
    ]
    policyDefinitionGroups: []
  }
}

resource assignment 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
  name: 'authored-assignment'
  properties: {
    policyDefinitionId: initiative.id
    definitionVersion: '1.2.3'
    enforcementMode: 'DoNotEnforce'
    notScopes: []
    resourceSelectors: []
    overrides: []
  }
}
