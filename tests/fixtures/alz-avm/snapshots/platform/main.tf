variable "location" {}
module "workspace" {
  source  = "Azure/avm-res-operationalinsights-workspace/azurerm"
  version = "0.5.1"

  name                                                  = "alz-platform-logs"
  resource_group_name                                   = "alz-management"
  location                                              = var.location
  enable_telemetry                                      = false
  log_analytics_workspace_retention_in_days              = 45
  log_analytics_workspace_sku                            = "PerGB2018"
  log_analytics_workspace_local_authentication_enabled   = false
}
module "connectivity" {
  source   = "./connectivity"
  location = var.location
}
resource "azurerm_management_group" "platform" {
  name         = "alz-platform"
  display_name = "ALZ platform"
}
output "location" {
  value = var.location
}
