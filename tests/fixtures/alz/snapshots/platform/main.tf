variable "prefix" {}
variable "location" {}
locals {
  name = "${var.prefix}-management"
}
module "management" {
  source   = "example.invalid/landinglens/management/azurerm"
  version  = "1.0.0"
  name     = local.name
  location = var.location
}
module "connectivity" {
  source   = "./connectivity"
  name     = "${var.prefix}-hub"
  location = var.location
}
resource "azurerm_management_group" "platform" {
  name         = var.prefix
  display_name = var.prefix
}
output "prefix" {
  value = var.prefix
}
output "location" {
  value = module.management.location
}
