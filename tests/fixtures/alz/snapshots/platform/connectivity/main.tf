variable "name" {}
variable "location" {}
resource "azurerm_virtual_network" "hub" {
  name                = var.name
  location            = var.location
  resource_group_name = "${var.name}-rg"
  address_space       = ["10.0.0.0/16"]
}
