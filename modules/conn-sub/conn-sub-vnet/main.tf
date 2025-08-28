terraform {
  backend "azurerm" {
    resource_group_name  = "ims-prd-conn-ne-rg-tfstate"
    storage_account_name = "prdconnalznst"
    container_name       = "tfstate"
    key                  = "connvNet.terraform.tfstate" # Path to the state file in the container
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


#############################################################
# Create "ims-prd-conn-ne-vnet-hub-01" connectivity-hub-vnet
#############################################################
resource "azurerm_virtual_network" "hubvnet" {
  provider            = azurerm.ims-prd-connectivity
  resource_group_name = azurerm_resource_group.conn.name
  name                = "ims-prd-conn-ne-vnet-hub-01"
  location            = var.location
  address_space       = ["192.168.0.0/22"]
  dns_servers = ["192.168.0.132"]

  encryption {
    enforcement = "AllowUnencrypted" 
  }

  # tags = {
   # Name        = "ims-prd-conn-ne-vnet-hub-01"
   # Environment = "prd"
   # DateCreated = "2025-08-01"
  # }
  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.service}-${var.hubspoke}-01"
	Environment = var.env
	DateCreated = formatdate("YYYY-MM-DD", timestamp())
  }
}

############################
# Create subnets in hubvnet
############################
# 1. Create "AzureFirewallSubnet" subnet for Firewall traffic at hub vNet
resource "azurerm_subnet" "AzureFirewallSubnet" {
  provider             = azurerm.ims-prd-connectivity
  resource_group_name  = azurerm_resource_group.conn.name
  virtual_network_name = azurerm_virtual_network.hubvnet.name
  name                 = "AzureFirewallSubnet"
  address_prefixes     = ["192.168.0.64/26"]

  # private_endpoint_network_policies_enabled = true

}

 # 2. Create "AzureFirewallManagementSubnet" subnet for Firewall Management traffic at hub vNet
resource "azurerm_subnet" "AzureFirewallManagementSubnet" {
  provider             = azurerm.ims-prd-connectivity
  resource_group_name  = azurerm_resource_group.conn.name
  virtual_network_name = azurerm_virtual_network.hubvnet.name
  name                 = "AzureFirewallManagementSubnet"
  address_prefixes     = ["192.168.1.64/26"]

  # private_endpoint_network_policies_enabled = true

}
# 3. Create "GatewaySubnet" subnet for Gateway traffic at hub vNet
resource "azurerm_subnet" "GatewaySubnet" {
  provider             = azurerm.ims-prd-connectivity
  resource_group_name  = azurerm_resource_group.conn.name
  virtual_network_name = azurerm_virtual_network.hubvnet.name
  name                 = "GatewaySubnet"
  address_prefixes     = ["192.168.0.0/26"]

  # private_endpoint_network_policies_enabled = true

  }
  # 4. Create "ims-prd-conn-ne-snet-dnsprin" subnet for inbound DNS private resolution traffic at hub vNet
resource "azurerm_subnet" "ims-prd-conn-ne-snet-dnsprin" {
  provider             = azurerm.ims-prd-connectivity
  resource_group_name  = azurerm_resource_group.conn.name
  virtual_network_name = azurerm_virtual_network.hubvnet.name
  name                 = "ims-prd-conn-ne-snet-dnsprin"
  address_prefixes     = ["192.168.0.128/26"]

  # private_endpoint_network_policies_enabled = true
  private_link_service_network_policies_enabled = true
  
  delegation {
    name = "dnsResolversDelegation"
    service_delegation {
      name    = "Microsoft.Network/dnsResolvers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}
# 5. Create "ims-prd-conn-ne-snet-dnsprout" subnet for outbound DNS private resolution traffic at hub vNet
resource "azurerm_subnet" "ims-prd-conn-ne-snet-dnsprout" {
  provider             = azurerm.ims-prd-connectivity
  resource_group_name  = azurerm_resource_group.conn.name
  virtual_network_name = azurerm_virtual_network.hubvnet.name
  name                 = "ims-prd-conn-ne-snet-dnsprout"
  address_prefixes     = ["192.168.0.192/26"]

  # private_endpoint_network_policies_enabled = true
  private_link_service_network_policies_enabled = true
  
  delegation {
    name = "dnsResolversDelegation"
    service_delegation {
      name    = "Microsoft.Network/dnsResolvers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}
# 6. Create "ims-prd-conn-ne-snet-pep" Private endpoint subnet at hub vNet
resource "azurerm_subnet" "ims-prd-conn-ne-snet-pep" {
  provider             = azurerm.ims-prd-connectivity
  resource_group_name  = azurerm_resource_group.conn.name
  virtual_network_name = azurerm_virtual_network.hubvnet.name
  name                 = "ims-prd-conn-ne-snet-pep"
  address_prefixes     = ["192.168.1.0/26"]

  # private_endpoint_network_policies_enabled = true
  private_link_service_network_policies_enabled = true
  
}