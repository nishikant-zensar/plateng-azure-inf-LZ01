terraform {
  backend "azurerm" {
    resource_group_name  = "ims-prd-conn-ne-rg-tfstate"
    storage_account_name = "prdconnalznst"
    container_name       = "tfstate"
    key                  = "vnetpeering.terraform.tfstate" # Path to the state file in the container
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

########################
# Peering Between vNets
########################
# Task 1: Peering between Hub and Mgmt vNet
resource "azurerm_virtual_network_peering" "hub_to_mgmt" {
  name                      = "ims-prd-conn-ne-vnet-hub-01-TO-ims-prd-mgmt-ne-vnet-01"
  resource_group_name       = "ims-prd-conn-ne-rg-network"
  virtual_network_name      = "ims-prd-conn-ne-vnet-hub-01"
  remote_virtual_network_id = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-mgmt-ne-vnet-01"
  provider                  = azurerm.ims-prd-connectivity

  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = true
  use_remote_gateways          = false

}

# Task 2: Peering between Hub and AVD vNet
resource "azurerm_virtual_network_peering" "hub_to_avd" {
  name                      = "ims-prd-conn-ne-vnet-hub-01-TO-ims-prd-avd-ne-vnet-01"
  resource_group_name       = "ims-prd-conn-ne-rg-network"
  virtual_network_name      = "ims-prd-conn-ne-vnet-hub-01"
  remote_virtual_network_id = "/subscriptions/9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef/resourceGroups/ims-prd-avd-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-avd-ne-vnet-01"
  provider                  = azurerm.ims-prd-connectivity

  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = true
  use_remote_gateways          = false

}

# Task 3: Peering between Mgmt and Hub vNet
resource "azurerm_virtual_network_peering" "mgmt_to_hub" {
  name                      = "ims-prd-mgmt-ne-vnet-01-TO-ims-prd-conn-ne-vnet-hub-01"
  resource_group_name       = "ims-prd-mgmt-ne-rg-network"
  virtual_network_name      = "ims-prd-mgmt-ne-vnet-01"
  remote_virtual_network_id = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01"
  provider                  = azurerm.ims-prd-management

  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = true
  use_remote_gateways          = false

}

# Task 4: Peering between Avd and Hub vNet
resource "azurerm_virtual_network_peering" "avd_to_hub" {
  name                      = "ims-prd-avd-ne-vnet-01-TO-ims-prd-conn-ne-vnet-hub-01"
  resource_group_name       = "ims-prd-avd-ne-rg-network"
  virtual_network_name      = "ims-prd-avd-ne-vnet-01"
  remote_virtual_network_id = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01"
  provider                  = azurerm.ims-prd-avd

  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = true
  use_remote_gateways          = false

}