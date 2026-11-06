targetScope = 'resourceGroup'

resource dashboard 'Microsoft.Portal/dashboards@2020-09-01-preview' = {
  name: 'capacity-review'
  location: 'westeurope'
  tags: {
    authored: 'fixture-not-a-billing-taxonomy'
  }
  properties: {
    lenses: [
      {
        order: 0
        parts: [
          {
            position: {
              x: 0
              y: 0
              colSpan: 4
              rowSpan: 3
            }
            metadata: {
              type: 'Extension/HubsExtension/PartType/MarkdownPart'
              settings: {
                content: {
                  settings: {
                    content: 'Authored structural fixture; not monitoring evidence.'
                  }
                }
              }
            }
          }
        ]
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: 'not-an-identity-designation'
  location: 'westeurope'
  tags: {}
  properties: {
    capacityReservation: {
      capacityReservationGroup: {
        id: '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/governance/providers/Microsoft.Compute/capacityReservationGroups/authored'
      }
    }
  }
}
