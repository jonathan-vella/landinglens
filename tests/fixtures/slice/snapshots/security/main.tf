variable "secure" { type = bool }
variable "dns_proxy" { type = bool }
resource "azurerm_storage_account" "logs" {
  name = "landinglenslogs"
  resource_group_name = "rg-management"
  location = "westeurope"
  https_traffic_only_enabled = var.secure
}
resource "azurerm_firewall_policy" "network" {
  name = "landinglenspolicy"
  resource_group_name = "rg-management"
  location = "westeurope"
  dns { proxy_enabled = var.dns_proxy }
}
