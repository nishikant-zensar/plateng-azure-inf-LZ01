output "platform_group_id" {
  value = azurerm_management_group.ims-root-platform.id
  description = "Platform Management group ID"
} 
output "environments_group_id" {
  value = azurerm_management_group.ims-root-environments.id
  description = "Environment Management group ID"
} 
output "sandbox_group_id" {
  value = azurerm_management_group.ims-root-sandbox.id
  description = "Sandbox Management group ID"
} 
output "decommissioned_group_id" {
  value = azurerm_management_group.ims-root-decommission.id
  description = "Decommissioned Management group ID"
} 
     
