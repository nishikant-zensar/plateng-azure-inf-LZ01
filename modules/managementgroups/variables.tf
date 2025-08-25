variable "root_management_group_id" {
  description = "The ID of the root management group (usually your tenant ID or 'root')."
  type        = string
  default     = "/providers/Microsoft.Management/managementGroups/684d2402-0ea6-442d-9ad7-4ef26b925ec5"
}
variable "connectivity_subscription_id" {
  description = "The Azure subscription ID for Connectivity"
  type        = string
  default     = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207"
}

variable "management_subscription_id" {
  description = "The Azure subscription ID for Management"
  type        = string
  default     = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36"
}

variable "avd_prd_subscription_id" {
  description = "The Azure subscription ID for AVD Production"
  type        = string
  default     = "/subscriptions/9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef"
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
  default     = "mgmtgrp.terraform.tfstate"
}