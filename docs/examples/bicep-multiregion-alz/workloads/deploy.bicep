targetScope = 'subscription'

param workloadResourceGroupName string = 'rg-alz-workloads'
param connectivitySubscriptionId string
param useSwedenRemoteGateway bool = true
param useGermanyRemoteGateway bool = true
param allowSwedenPeeringAccess bool = true

module workloadNetwork './main.bicep' = {
  name: 'alz-workload-network'
  scope: resourceGroup(workloadResourceGroupName)
  params: {
    connectivitySubscriptionId: connectivitySubscriptionId
    useSwedenRemoteGateway: useSwedenRemoteGateway
    useGermanyRemoteGateway: useGermanyRemoteGateway
    allowSwedenPeeringAccess: allowSwedenPeeringAccess
  }
}
