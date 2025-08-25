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

# 3. Resource Groups for ims-prd-avd (avd subscription)
resource "azurerm_resource_group" "avd" {
  provider = azurerm.ims-prd-avd
  name     = "ims-prd-avd-ne-rg-network"
  location = var.location
  
  tags = {
    Name        = "ims-prd-avd-ne-rg-network"
    Environment = "prd"
    DateCreated = "2025-08-01"
  }
}

# Create Additional RG's in AVD MG
# 1. Create Pool RG in AVD MG
resource "azurerm_resource_group" "avdpool" {
  provider = azurerm.ims-prd-avd
  name     = "ims-prd-avd-ne-rg-pool"
  location = var.location
  
  tags = {
    Name        = "ims-prd-avd-ne-rg-pool"
    Environment = "prd"
    DateCreated = "2025-08-01"
  }
}
# 2. Create Personal RG in AVD MG
resource "azurerm_resource_group" "avdpsnl" {
  provider = azurerm.ims-prd-avd
  name     = "ims-prd-avd-ne-rg-psnl"
  location = var.location
  
  tags = {
    Name        = "ims-prd-avd-ne-rg-psnl"
    Environment = "prd"
    DateCreated = "2025-08-01"
  }
}
