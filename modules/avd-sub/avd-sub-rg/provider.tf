provider "azurerm" {
  alias           = "ims-prd-avd"
  subscription_id = "9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef"
  tenant_id       = "684d2402-0ea6-442d-9ad7-4ef26b925ec5"
  client_id       = "74925104-cd8b-47e5-b29a-83a75a2f4ca6"
  resource_provider_registrations = "none"
  features {}
}