terraform {
  backend "azurerm" {
    resource_group_name  = "ims-prd-mgmt-ne-rg-tfstate"
    storage_account_name = "prdmgmtalznst"
    container_name       = "tfstate"
    key                  = "mgmtvNet.terraform.tfstate" # Path to the state file in the container
    use_oidc_auth        = true
    use_azuread_auth     = true
  }
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.0"  
}

provider "azurerm" {
  features {}
}

####################################################
# Create "ims-prd-mgmt-ne-vnet-01" management vNet
####################################################
resource "azurerm_virtual_network" "mgmtvnet" {
  provider            = azurerm.ims-prd-management
  resource_group_name = azurerm_resource_group.mgmt.name
  name                = "ims-prd-mgmt-ne-vnet-01"
  location            = var.location
  address_space       = ["192.168.4.0/22"]
  dns_servers = ["192.168.0.132"]

  encryption {
    enforcement = "AllowUnencrypted"
  }

  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.service}-01"
	Environment = var.env
	DateCreated = formatdate("YYYY-MM-DD", timestamp())
  critical  = "true"
  Application = ""
  Owner = ""
  CostCentre = ""
  Datadog = ""
  SNApplicationService =""
  SNResolver = ""
  SNEnvironment = ""
  ServiceCategory = ""
  }

}
##############################
# Create Subnets in mgmt vnet
##############################
# 1. Create "ims-prd-mgmt-ne-snet-security" subnet for mgmt security traffic at mgmt vNet
resource "azurerm_subnet" "ims-prd-mgmt-ne-snet-security" {
  provider             = azurerm.ims-prd-management
  resource_group_name  = azurerm_resource_group.mgmt.name
  virtual_network_name = azurerm_virtual_network.mgmtvnet.name
  name                 = "ims-prd-mgmt-ne-snet-security"
  address_prefixes     = ["192.168.4.0/26"]

  # private_endpoint_network_policies_enabled = true
  private_link_service_network_policies_enabled = true
  
}
# 2. Create "ims-prd-mgmt-ne-snet-system" subnet for mgmt system traffic at mgmt vNet
resource "azurerm_subnet" "ims-prd-mgmt-ne-snet-system" {
  provider             = azurerm.ims-prd-management
  resource_group_name  = azurerm_resource_group.mgmt.name
  virtual_network_name = azurerm_virtual_network.mgmtvnet.name
  name                 = "ims-prd-mgmt-ne-snet-system"
  address_prefixes     = ["192.168.4.64/26"]

  # private_endpoint_network_policies_enabled = true
  private_link_service_network_policies_enabled = true

}
# 3. Create "ims-prd-mgmt-ne-snet-keyvault" subnet for mgmt keyvault traffic at mgmt vNet
resource "azurerm_subnet" "ims-prd-mgmt-ne-snet-keyvault" {
  provider             = azurerm.ims-prd-management
  resource_group_name  = azurerm_resource_group.mgmt.name
  virtual_network_name = azurerm_virtual_network.mgmtvnet.name
  name                 = "ims-prd-mgmt-ne-snet-keyvault"
  address_prefixes     = ["192.168.4.128/26"]
  
  # private_endpoint_network_policies_enabled = true
  private_link_service_network_policies_enabled = true

}
# 4. Create "ims-prd-mgmt-ne-snet-pep" subnet for mgmt private endpoint traffic at mgmt vNet
resource "azurerm_subnet" "ims-prd-mgmt-ne-snet-pep" {
  provider             = azurerm.ims-prd-management
  resource_group_name  = azurerm_resource_group.mgmt.name
  virtual_network_name = azurerm_virtual_network.mgmtvnet.name
  name                 = "ims-prd-mgmt-ne-snet-pep"
  address_prefixes     = ["192.168.4.192/26"]

  # private_endpoint_network_policies_enabled = true
  private_link_service_network_policies_enabled = true

}
