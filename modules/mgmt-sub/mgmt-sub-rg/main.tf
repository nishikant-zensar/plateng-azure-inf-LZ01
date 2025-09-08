terraform {
  backend "azurerm" {
    resource_group_name  = "ims-prd-mgmt-ne-rg-tfstate"
    storage_account_name = "prdmgmtalznst"
    container_name       = "tfstate"
    key                  = "mgmtrg.terraform.tfstate" # Path to the state file in the container
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
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.type}-${var.suffix}"
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

# Create Additional RG's in Management MG
# 1. Create defender RG in Management MG
resource "azurerm_resource_group" "mgmtdef" {
  provider = azurerm.ims-prd-management
  name     = "ims-prd-mgmt-ne-rg-defender"
  location = var.location

  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.type}-defender"
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
# 2. Create Key Vault RG in Management MG
resource "azurerm_resource_group" "mgmtkv" {
  provider = azurerm.ims-prd-management
  name     = "ims-prd-mgmt-ne-rg-keyvault"
  location = var.location
  
  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.type}-keyvault"
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
# 3. Create log-security RG in Management MG
resource "azurerm_resource_group" "mgmtlsec" {
  provider = azurerm.ims-prd-management
  name     = "ims-prd-mgmt-ne-rg-log-security"
  location = var.location
  
  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.type}-log-security"
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
# 4. Create log-system RG in Management MG
resource "azurerm_resource_group" "mgmtlsys" {
  provider = azurerm.ims-prd-management
  name     = "ims-prd-mgmt-ne-rg-log-system"
  location = var.location

  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.type}-log-system"
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
# 5. Create Purview RG in Management MG
resource "azurerm_resource_group" "mgmtpur" {
  provider = azurerm.ims-prd-management
  name     = "ims-prd-mgmt-ne-rg-purview"
  location = var.location
  
  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.type}-purview"
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
# 6. Create storage RG in Management MG
resource "azurerm_resource_group" "mgmtst" {
  provider = azurerm.ims-prd-management
  name     = "ims-prd-mgmt-ne-rg-storage"
  location = var.location
  
  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.type}-storage"
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
