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
variable "sub" { default = "conn" }
variable "region" { default = "ne" }
variable "type" { default = "rg" }
variable "service" { default = "vnet" }
variable "service2" { default = "pip" }
variable "hubspoke" { default = "hub" }
variable "azfw" { default = "afw" }
variable "suffix" { default = "network" }
variable "ipg" { default = "ZscallerIPg" }