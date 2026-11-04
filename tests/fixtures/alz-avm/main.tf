variable "location" {
  default = "australiaeast"
}
module "platform" {
  source   = "example.invalid/landinglens/avm-platform/azurerm"
  version  = "1.0.0"
  location = var.location
}
resource "azurerm_resource_group" "application" {
  name     = "application"
  location = module.platform.location
}
