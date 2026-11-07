targetScope = 'subscription'

type HubConfig = {
  name: string
  prefix: string
  enabled: bool
}

param hubs HubConfig[] = [
  { name: 'west', prefix: '10.40.0.0/22', enabled: true }
  { name: 'north', prefix: '10.41.0.0/22', enabled: true }
]

var groups = [for hub in hubs: 'rg-${hub.name}']
var names = map(hubs, hub => hub.name)

resource existingGroups 'Microsoft.Resources/resourceGroups@2025-04-01' existing = [
  for (hub, i) in hubs: {
    name: groups[i]
  }
]

module networks './compatibility-child.bicep' = [
  for (hub, i) in hubs: if (hub.enabled) {
    name: 'network-${i}'
    scope: existingGroups[i]
    params: {
      name: any(null)
      fallbackName: names[i]
      prefix: hub.prefix
    }
  }
]

module consumer './compatibility-child.bicep' = if (hubs[0].enabled) {
  name: 'consumer'
  scope: existingGroups[1]
  params: {
    name: '${networks[0].outputs.name}-consumer'
    fallbackName: 'unused'
    prefix: '10.42.0.0/22'
  }
}
