param location string = 'australiaeast'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'landinglens-fixture'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}
