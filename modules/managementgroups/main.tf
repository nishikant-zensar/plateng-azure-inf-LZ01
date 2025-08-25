terraform {
  backend "azurerm" {
    resource_group_name  = "ims-prd-mgmt-ne-rg-mgmttf"
    storage_account_name = "prdmgmtgrstr"
    container_name       = "tfstate"
    key                  = "mgmtgrp.terraform.tfstate" # Path to the state file in the container
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

# provider "azurerm" {
#  features {}
# }

####################################
# Create the Top Management Group  #
####################################
resource "azurerm_management_group" "TescoIMSRootMG" {
  name         = "IMS-Root"       # Unique name for the management group
  display_name = "IMS-Root"       # Friendly display name
  parent_management_group_id = var.root_management_group_id
}

##############################
# Create 1st Level Child MGs #
##############################
# Platform Root Management Group
resource "azurerm_management_group" "ims-root-platform" {
  name                          = "ims-root-platform"
  display_name                  = "ims-root-platform"
  parent_management_group_id    = azurerm_management_group.TescoIMSRootMG.id
  depends_on = [
    azurerm_management_group.TescoIMSRootMG
  ]
}
# Environments Root Management Group
resource "azurerm_management_group" "ims-root-environments" {
  name                          = "ims-root-environments"
  display_name                  = "ims-root-environments"
  parent_management_group_id    = azurerm_management_group.TescoIMSRootMG.id
  depends_on = [
    azurerm_management_group.TescoIMSRootMG
  ]
}
# Sandbox Root Management Group
resource "azurerm_management_group" "ims-root-sandbox" {
  name                          = "ims-root-sandbox"
  display_name                  = "ims-root-sandbox"
  parent_management_group_id    = azurerm_management_group.TescoIMSRootMG.id
  depends_on = [
    azurerm_management_group.TescoIMSRootMG
  ]
}
# Decommission Root Management Group
resource "azurerm_management_group" "ims-root-decommission" {
  name                          = "ims-root-decommission"
  display_name                  = "ims-root-decommission"
  parent_management_group_id    = azurerm_management_group.TescoIMSRootMG.id
  depends_on = [
    azurerm_management_group.TescoIMSRootMG
  ]
}

#################################################
# Create Child MGs under "ims-root-platform" MG #
################################################
# 1. prd platform MG under "ims-root-platform" MG
resource "azurerm_management_group" "ims-platform-prd" {
  name                          = "ims-platform-prd"
  display_name                  = "ims-platform-prd"
  parent_management_group_id    = azurerm_management_group.ims-root-platform.id
  depends_on = [
    azurerm_management_group.ims-root-platform
  ]
}

# 2. ppte platform MG under "ims-root-platform" MG
resource "azurerm_management_group" "ims-platform-ppte" {
  name                          = "ims-platform-ppte"
  display_name                  = "ims-platform-ppte"
  parent_management_group_id    = azurerm_management_group.ims-root-platform.id
  depends_on = [
    azurerm_management_group.ims-root-platform
  ]
}

#####################################################
# Create Child MGs under "ims-root-environments" MG #
#####################################################
# 1.  dev MG under "ims-root-environments" MG
resource "azurerm_management_group" "ims-env-dev" {
  name                          = "ims-env-dev"
  display_name                  = "ims-env-dev"
  parent_management_group_id    = azurerm_management_group.ims-root-environments.id
  depends_on = [
    azurerm_management_group.ims-root-environments
  ]
}

# 2. ppe (pre-production) MG under "ims-root-environments" MG
resource "azurerm_management_group" "ims-env-ppe" {
  name                          = "ims-env-ppe"
  display_name                  = "ims-env-ppe"
  parent_management_group_id    = azurerm_management_group.ims-root-environments.id
  depends_on = [
    azurerm_management_group.ims-root-environments
  ]
}
# 3. test MG under "ims-root-environments" MG
resource "azurerm_management_group" "ims-env-test" {
  name                          = "ims-env-test"
  display_name                  = "ims-env-test"
  parent_management_group_id    = azurerm_management_group.ims-root-environments.id
  depends_on = [
    azurerm_management_group.ims-root-environments
  ]
}
# 4. prd MG under "ims-root-environments" MG
resource "azurerm_management_group" "ims-env-prd" {
  name                          = "ims-env-prd"
  display_name                  = "ims-env-prd"
  parent_management_group_id    = azurerm_management_group.ims-root-environments.id
  depends_on = [
    azurerm_management_group.ims-root-environments
  ]
}