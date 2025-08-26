variable "root_management_group_id" {
  description = "The ID of the root management group (usually your tenant ID or 'root')."
  type        = string
  default     = "/providers/Microsoft.Management/managementGroups/TescoIMSRootMG"
}

variable "backend_resource_group_name" {
  description = "The name of the backend resource group"
  type        = string
}

variable "backend_storage_account_name" {
  description = "The name of the backend storage account"
  type        = string
}

variable "backend_container_name" {
  description = "The name of the backend container"
  type        = string
}

variable "backend_key" {
  description = "The key for the backend state file"
  type        = string
  default     = "hubspoke.terraform.tfstate"
}
variable "location" {
  description = "Location for resource creation"
  type        = string
  default     = "northeurope"
}

variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
  default     = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207"
}

variable "sub1" {
  description = "Subscription ID for sub1"
  type        = string
  default     = "b63f4e55-499d-4984-9375-f17853ff6e36"
}
variable "resource_group_name" {
  description = "Resource Group Name"
  type        = string
  default     = "ims-prd-conn-ne-rg-network"
}

variable "rgkv" {
  description = "Resource Group Name"
  type        = string
  default     = "ims-prd-mgmt-ne-rg-keyvault"
}

#variable "availability_zones" {
#  description = "List of Availability Zones"
#  type        = list(string)
#  default     = []
# }

# variable "firewall_sku_name" {
#  description = "Firewall SKU (AZFW_VNet or AZFW_Hub)"
#  type        = string
# }

# variable "firewall_sku_tier" {
#  description = "Firewall SKU Tier (Standard, Premium, or Basic)"
#  type        = string
# }

variable "location" {
  description = "Firewall Policy Region"
  type        = string
  default     = "northeurope"
}

#variable "policy_sku" {
#  description = "Firewall Policy Tier (Standard or Premium)"
#  type        = string
# }

variable "vnet" {
  description = "Virtual Network Name"
  type        = string
  default     = "ims-prd-conn-ne-vnet-hub-01"
}

variable "vnetkv" {
  description = "Virtual Network Name"
  type        = string
  default     = "ims-prd-mgmt-ne-vnet-01"
}

variable "fw_subnet" {
  description = "Subnet Name"
  type        = string
  default     = "AzureFirewallSubnet"
}

variable "dnspinsubnet" {
  description = "Subnet Name"
  type        = string
  default     = "ims-prd-conn-ne-snet-dnsprin"
}
variable "dnspoutsubnet" {
  description = "Subnet Name"
  type        = string
  default     = "ims-prd-conn-ne-snet-dnsprout"
}

variable "kvsubnet" {
  description = "Subnet Name"
  type        = string
  default     = "ims-prd-mgmt-ne-snet-keyvault"
}

#variable "subnet_prefix" {
#  description = "Address prefix for firewall subnet"
#  type        = string
# }

variable "public_ip" {
  description = "Name of the Public IP for Firewall"
  type        = string
  default     = "ims-prd-conn-ne-pip-afw-01"
}

variable "enable_threat_intel" {
  description = "Enable Threat Intelligence mode (Off, Alert, Deny)"
  type        = string
  default     = "Alert"
}

variable "idps_mode" {
  description = "IDPS mode (Off, Alert, Deny)"
  type        = string
  default     = "Alert"

}
variable "private_dns_zones" {
  type    = list(string)
  default = ["privatelink.sql.azuresynapse.net", "privatelink.servicebus.windows.net", "privatelink.analysis.windows.net", "privatelink.pbidedicated.windows.net", "privatelink.tip1.powerquery.microsoft.com", "privatelink.wvd.microsoft.com", "privatelink.wvd.microsoft.com", "privatelink-global.wvd.microsoft.com", "privatelink.database.windows.net", "privatelink.postgres.database.azure.com", "privatelink.redis.cache.windows.net", "privatelink.mysql.database.azure.com", "privatelink.servicebus.windows.net", "privatelink.vaultcore.azure.net", "privatelink.blob.core.windows.net", "privatelink.table.core.windows.net", "privatelink.queue.core.windows.net", "privatelink.file.core.windows.net", "privatelink.web.core.windows.net", "privatelink.dfs.core.windows.net"]
}
variable "org" { default = "ims" }
variable "env" { default = "prd" }
variable "sub" { default = "mgmt" }
variable "region" { default = "ne" }
variable "type" { default = "rg" }
variable "service" { default = "nsg" }
variable "service2" { default = "rt" }
variable "suffix" { default = "network" }
variable "inout" { default = "in" }