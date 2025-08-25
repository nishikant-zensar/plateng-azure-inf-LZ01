terraform {
  backend "azurerm" {
    resource_group_name  = "ims-prd-lz-ne-rg-terraformstate"
    storage_account_name = "imslandingznstr"
    container_name       = "tfstate"
    key                  = "hubspoke.terraform.tfstate" # Path to the state file in the container
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

# 2. Resource Groups in ims-prd-management (Management subscription)
resource "azurerm_resource_group" "mgmt" {
  provider = azurerm.ims-prd-management
  name     = "ims-prd-mgmt-ne-rg-network"
  location = var.location
  
  tags = {
    Name        = "ims-prd-mgmt-ne-rg-network"
    Environment = "prd"
    DateCreated = "2025-08-01"
  }
}

# Create Additional RG's in Management MG
# 1. Create defender RG in Management MG
resource "azurerm_resource_group" "mgmtdef" {
  provider = azurerm.ims-prd-management
  name     = "ims-prd-mgmt-ne-rg-defender"
  location = var.location
 
  tags = {
    Name        = "ims-prd-mgmt-ne-rg-defender"
    Environment = "prd"
    DateCreated = "2025-08-01"
  }
}
# 2. Create Key Vault RG in Management MG
resource "azurerm_resource_group" "mgmtkv" {
  provider = azurerm.ims-prd-management
  name     = "ims-prd-mgmt-ne-rg-keyvault"
  location = var.location
  
  tags = {
    Name        = "ims-prd-mgmt-ne-rg-keyvault"
    Environment = "prd"
    DateCreated = "2025-08-01"
  }
}
# 3. Create log-security RG in Management MG
resource "azurerm_resource_group" "mgmtlsec" {
  provider = azurerm.ims-prd-management
  name     = "ims-prd-mgmt-ne-rg-log-security"
  location = var.location
  
  tags = {
    Name        = "ims-prd-mgmt-ne-rg-log-security"
    Environment = "prd"
    DateCreated = "2025-08-01"
  }
}
# 4. Create log-system RG in Management MG
resource "azurerm_resource_group" "mgmtlsys" {
  provider = azurerm.ims-prd-management
  name     = "ims-prd-mgmt-ne-rg-log-system"
  location = var.location

  tags = {
    Name        = "ims-prd-mgmt-ne-rg-log-system"
    Environment = "prd"
    DateCreated = "2025-08-01"
  }
}
# 5. Create Purview RG in Management MG
resource "azurerm_resource_group" "mgmtpur" {
  provider = azurerm.ims-prd-management
  name     = "ims-prd-mgmt-ne-rg-purview"
  location = var.location
  
  tags = {
    Name        = "ims-prd-mgmt-ne-rg-purview"
    Environment = "prd"
    DateCreated = "2025-08-01"
  }
}
# 6. Create storage RG in Management MG
resource "azurerm_resource_group" "mgmtstr" {
  provider = azurerm.ims-prd-management
  name     = "ims-prd-mgmt-ne-rg-storage"
  location = var.location
  
  tags = {
    Name        = "ims-prd-mgmt-ne-rg-storage"
    Environment = "prd"
    DateCreated = "2025-08-01"
  }
}
