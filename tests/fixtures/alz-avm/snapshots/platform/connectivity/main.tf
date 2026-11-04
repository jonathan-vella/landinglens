variable "location" {}
resource "azurerm_virtual_network" "hub" {
  name                = "alz-hub"
  location            = var.location
  resource_group_name = "alz-connectivity"
  address_space       = ["10.0.0.0/16"]
}
