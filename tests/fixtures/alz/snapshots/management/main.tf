variable "name" {}
variable "location" {}
resource "azurerm_log_analytics_workspace" "platform" {
  name                = var.name
  location            = var.location
  resource_group_name = "${var.name}-rg"
  sku                 = "PerGB2018"
  retention_in_days   = 30
}
output "location" {
  value = var.location
}
