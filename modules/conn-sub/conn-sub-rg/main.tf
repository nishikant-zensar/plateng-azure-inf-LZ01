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
# Create Network RG in Connectivity MG
# 1. Resource Group in ims-prd-connectivity (Connectivity subscription) 
resource "azurerm_resource_group" "conn" {
  provider = azurerm.ims-prd-connectivity
  name     = "ims-prd-conn-ne-rg-network"
  location = var.location
  tags = {
    Name        = "ims-prd-conn-ne-rg-network"
    Environment = "prd"
    DateCreated = "2025-08-01"
  }
  }
