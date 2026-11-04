variable "location" {
  default = "australiaeast"
}
variable "prefix" {
  default = "root"
}
locals {
  name = "${var.prefix}-platform"
}
module "platform" {
  source   = "example.invalid/landinglens/alz/azurerm"
  version  = "1.0.0"
  prefix   = local.name
  location = var.location
}
resource "azurerm_resource_group" "application" {
  name     = "${module.platform.prefix}-application"
  location = module.platform.location
}
output "platform_name" {
  value = module.platform.prefix
}
