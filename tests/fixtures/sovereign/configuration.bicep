targetScope = 'resourceGroup'

resource first 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: 'authored-first-not-a-classification'
  location: 'westeurope'
  tags: {
    arbitrary: 'PRIVATE-NOT-FOR-REPORTING'
  }
  properties: {}
}

resource second 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: 'authored-second-not-recovery-proof'
  location: 'northeurope'
  tags: {}
  properties: {}
}
