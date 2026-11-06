targetScope = 'subscription'

resource definition 'Microsoft.ManagedServices/registrationDefinitions@2022-10-01' = {
  name: '11111111-1111-1111-1111-111111111111'
  properties: {
    registrationDefinitionName: 'Authored offline fixture'
    managedByTenantId: '22222222-2222-2222-2222-222222222222'
    authorizations: [
      {
        principalId: '33333333-3333-3333-3333-333333333333'
        roleDefinitionId: 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
      }
    ]
    eligibleAuthorizations: []
  }
}

resource assignment 'Microsoft.ManagedServices/registrationAssignments@2022-10-01' = {
  name: '44444444-4444-4444-4444-444444444444'
  properties: {
    registrationDefinitionId: definition.id
  }
}

resource view 'Microsoft.CostManagement/views@2019-11-01' = {
  name: 'authored-view'
  properties: {
    displayName: 'Authored offline fixture, not a financial report'
    scope: subscription().id
    chart: 'Table'
    metric: 'ActualCost'
    query: {
      type: 'Usage'
      timeframe: 'MonthToDate'
    }
  }
}
