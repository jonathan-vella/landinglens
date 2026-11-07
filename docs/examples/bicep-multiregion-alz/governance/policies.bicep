targetScope = 'managementGroup'

param deployNetworkPolicy bool
param deployTagPolicy bool

var alzPolicyLibrary = '../upstream/templates/core/governance/lib/alz'
var denySubnetWithoutUdr = loadJsonContent('${alzPolicyLibrary}/Deny-Subnet-Without-Udr.alz_policy_definition.json')
var auditMandatoryTags = loadJsonContent('${alzPolicyLibrary}/Audit-Tags-Mandatory.alz_policy_definition.json')

resource denySubnetWithoutUdrDefinition 'Microsoft.Authorization/policyDefinitions@2023-04-01' = if (deployNetworkPolicy) {
  name: denySubnetWithoutUdr.name
  properties: denySubnetWithoutUdr.properties
}

resource auditMandatoryTagsDefinition 'Microsoft.Authorization/policyDefinitions@2023-04-01' = if (deployTagPolicy) {
  name: auditMandatoryTags.name
  properties: auditMandatoryTags.properties
}

resource denySubnetWithoutUdrAssignment 'Microsoft.Authorization/policyAssignments@2023-04-01' = if (deployNetworkPolicy) {
  name: 'alz-deny-subnet-without-udr'
  properties: {
    displayName: 'ALZ: require a user-defined route on workload subnets'
    description: 'Fictional assignment of the pinned upstream ALZ policy.'
    policyDefinitionId: denySubnetWithoutUdrDefinition.id
    parameters: {
      effect: {
        value: 'Deny'
      }
    }
  }
}

resource auditMandatoryTagsAssignment 'Microsoft.Authorization/policyAssignments@2023-04-01' = if (deployTagPolicy) {
  name: 'alz-audit-mandatory-tags'
  properties: {
    displayName: 'ALZ: audit mandatory resource tags'
    description: 'Fictional assignment of the pinned upstream ALZ policy.'
    policyDefinitionId: auditMandatoryTagsDefinition.id
    parameters: {
      effect: {
        value: 'Audit'
      }
      mandatoryTags: {
        value: [
          'owner'
          'costcenter'
        ]
      }
    }
  }
}
