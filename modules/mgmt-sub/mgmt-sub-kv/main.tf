terraform {
  backend "azurerm" {
    resource_group_name  = "ims-prd-mgmt-ne-rg-tfstate"
    storage_account_name = "prdmgmtalznst"
    container_name       = "tfstate"
    key                  = "mgmtkv.terraform.tfstate" # Path to the state file in the container
    use_oidc_auth        = true
    use_azuread_auth     = true
  }
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.36"
    }
  }
  required_version = ">= 1.9, < 2.0"  
}

#########################
# Create Azure Key Vault
#########################

provider "azurerm" {
  features{}
  alias           = "ims-prd-management"
  subscription_id = "b63f4e55-499d-4984-9375-f17853ff6e36"
  tenant_id       = "684d2402-0ea6-442d-9ad7-4ef26b925ec5"
  client_id       = "74925104-cd8b-47e5-b29a-83a75a2f4ca6"
}

# Data sources for existing resources
# data "azurerm_virtual_network" "vnet" {
#  name                = "ims-prd-mgmt-ne-vnet-01"
#  resource_group_name = "ims-prd-mgmt-ne-rg-keyvault"
#  provider = azurerm.ims-prd-management
#}

data "azurerm_resource_group" "connsub" {
  name     = "ims-prd-conn-ne-rg-network"
  provider = azurerm.ims-prd-connectivity
}
data "azurerm_resource_group" "mgmtsub" {
  name     = "ims-prd-mgmt-ne-rg-keyvault"
  provider = azurerm.ims-prd-management
}

data "azurerm_resource_group" "mgmtsub2" {
  name     = "ims-prd-mgmt-ne-rg-network"
  provider = azurerm.ims-prd-management
}

# data "azurerm_subnet" "subnet" {
#  name                 = "subnet-kv" # You must specify the actual subnet name
#  virtual_network_name = data.azurerm_virtual_network.vnet.name
#  resource_group_name  = data.azurerm_resource_group.mgmtsub.name
# }

# data "azurerm_private_dns_zone" "dnszone" {
#  name                = "privatelink.vaultcore.azure.net"
#  resource_group_name = data.azurerm_resource_group.mgmtsub.name
# }

# Create Key Vault
resource "azurerm_key_vault" "kv" {
  provider                    = azurerm.ims-prd-management
  # subscription                = ["b63f4e55-499d-4984-9375-f17853ff6e36"]
  name                        = "ims-prd-mgmt-ne-kv-01"
  location                    = var.location
  resource_group_name         = data.azurerm_resource_group.mgmtsub.name
  sku_name                    = "premium"
  tenant_id                   = "684d2402-0ea6-442d-9ad7-4ef26b925ec5"
  # soft_delete_enabled         = true
  purge_protection_enabled    = true
  soft_delete_retention_days  = 90

  public_network_access_enabled = false
  enable_rbac_authorization     = true

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
  }

  # Enable deployment access
  enabled_for_deployment          = true
  enabled_for_disk_encryption     = true
  enabled_for_template_deployment = true

  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.service}-01"
	Environment = var.env
	DateCreated = formatdate("YYYY-MM-DD", timestamp())
  }
}

# Private Endpoint
resource "azurerm_private_endpoint" "kvpep" {
  provider              = azurerm.ims-prd-management
  # subscription        = var.sub1
  resource_group_name = data.azurerm_resource_group.mgmtsub.name
  location            = var.location
  name                = "ims-prd-mgmt-ne-pep-kv-01"
  subnet_id           = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-mgmt-ne-vnet-01/subnets/ims-prd-mgmt-ne-snet-keyvault"

  private_service_connection {
    name                           = "kv-priv-conn"
    private_connection_resource_id = azurerm_key_vault.kv.id
    is_manual_connection           = false
    subresource_names              = ["vault"]
  }
  # virtual_network_id    = var.vnetkv
  
}
# Create Private DNS Zone
resource "azurerm_private_dns_zone" "dnszone" {
  provider              = azurerm.ims-prd-management
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = data.azurerm_resource_group.mgmtsub2.name
}

# Private DNS zone association
resource "azurerm_private_dns_zone_virtual_network_link" "dnslink" {
  provider              = azurerm.ims-prd-management
  name                  = "kv-dnslink"
  resource_group_name   = data.azurerm_resource_group.mgmtsub2.name
  private_dns_zone_name = azurerm_private_dns_zone.dnszone.name
  virtual_network_id    = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-mgmt-ne-vnet-01"
}

resource "azurerm_private_dns_a_record" "kv_record" {
  provider            = azurerm.ims-prd-management
  name                = azurerm_key_vault.kv.name
  zone_name           = "privatelink.vaultcore.azure.net"
  resource_group_name = data.azurerm_resource_group.mgmtsub2.name
  records             = [azurerm_private_endpoint.kvpep.private_service_connection[0].private_ip_address]
  ttl                 = 300
}

#################################
# Create Log Analytics Workspace
#################################
resource "azurerm_log_analytics_workspace" "log_analytics" {
  provider              = azurerm.ims-prd-management
  # subscription        = ["b63f4e55-499d-4984-9375-f17853ff6e36"]
  resource_group_name = data.azurerm_resource_group.mgmtsub2.name
  name                = "ims-prd-mgmt-ne-log-analytics-01"
  location            = var.location
  
  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.service2}-01"
	Environment = var.env
	DateCreated = formatdate("YYYY-MM-DD", timestamp())
  }
}