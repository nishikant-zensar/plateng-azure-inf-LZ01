terraform {
  backend "azurerm" {
    resource_group_name  = "ims-prd-avd-ne-rg-tfstate"
    storage_account_name = "prdavdalznst"
    container_name       = "tfstate"
    key                  = "avdvNet.terraform.tfstate" # Path to the state file in the container
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


###########################################
# Create "ims-prd-avd-ne-vnet-01" avd vNet
###########################################
resource "azurerm_virtual_network" "avdvnet" {
  provider            = azurerm.ims-prd-avd
  resource_group_name = azurerm_resource_group.avd.name
  name                = "ims-prd-avd-ne-vnet-01"
  location            = var.location
  address_space       = ["192.168.8.0/22"]
  dns_servers = ["192.168.0.132"]

  encryption {
    enforcement = "AllowUnencrypted"
  }

  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.type}-01"
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

#############################
# Create Subnets in avd vnet
#############################
# 1. Create "ims-prd-avd-ne-snet-pool" subnet for avd pool traffic at avd vNet
resource "azurerm_subnet" "ims-prd-avd-ne-snet-pool" {
  provider             = azurerm.ims-prd-avd
  resource_group_name  = azurerm_resource_group.avd.name
  virtual_network_name = azurerm_virtual_network.avdvnet.name
  name                 = "ims-prd-avd-ne-snet-pool"
  address_prefixes     = ["192.168.8.0/24"]

  # private_endpoint_network_policies_enabled = true
  private_link_service_network_policies_enabled = true

}

# 2. Create "ims-prd-avd-ne-snet-personal" subnet for avd personal traffic at avd vNet
resource "azurerm_subnet" "ims-prd-avd-ne-snet-personal" {
  provider             = azurerm.ims-prd-avd
  resource_group_name  = azurerm_resource_group.avd.name
  virtual_network_name = azurerm_virtual_network.avdvnet.name
  name                 = "ims-prd-avd-ne-snet-personal"
  address_prefixes     = ["192.168.9.0/24"]

  # private_endpoint_network_policies_enabled = true
  private_link_service_network_policies_enabled = true
}

# 3. Create "ims-prd-avd-ne-snet-pep" subnet for avd private endpoint traffic at avd vNet
resource "azurerm_subnet" "ims-prd-avd-ne-snet-pep" {
  provider             = azurerm.ims-prd-avd
  resource_group_name  = azurerm_resource_group.avd.name
  virtual_network_name = azurerm_virtual_network.avdvnet.name
  name                 = "ims-prd-avd-ne-snet-pep"
  address_prefixes     = ["192.168.11.128/26"]

  # private_endpoint_network_policies_enabled = true
  private_link_service_network_policies_enabled = true

}

# 4. Create "ims-prd-avd-ne-snet-mgmt" subnet for avd management traffic at avd vNet
resource "azurerm_subnet" "ims-prd-avd-ne-snet-mgmt" {
  provider             = azurerm.ims-prd-avd
  resource_group_name  = azurerm_resource_group.avd.name
  virtual_network_name = azurerm_virtual_network.avdvnet.name
  name                 = "ims-prd-avd-ne-snet-mgmt"
  address_prefixes     = ["192.168.10.0/24"]

  # private_endpoint_network_policies_enabled = true
  private_link_service_network_policies_enabled = true

}