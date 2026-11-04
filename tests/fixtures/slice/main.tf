variable "secure" { default = true }
variable "dns_proxy" { default = true }
module "alz" { source = "../alz" }
module "security" {
  source = "example/security/azurerm"
  version = "1.0.0"
  secure = var.secure
  dns_proxy = var.dns_proxy
}
