targetScope = 'resourceGroup'

resource hsm 'Microsoft.KeyVault/managedHSMs@2024-11-01' = {
  name: 'reviewed-hsm'
  location: 'westeurope'
  sku: {
    family: 'B'
    name: 'Standard_B1'
  }
  properties: {
    publicNetworkAccess: 'Disabled'
    enablePurgeProtection: true
  }
}

resource machine 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: 'reviewed-machine'
  location: 'westeurope'
  properties: {
    osProfile: {
      linuxConfiguration: {
        provisionVMAgent: true
        patchSettings: {
          assessmentMode: 'AutomaticByPlatform'
          patchMode: 'ImageDefault'
        }
      }
    }
  }
}
