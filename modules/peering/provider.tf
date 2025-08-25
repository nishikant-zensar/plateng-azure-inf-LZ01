provider "azurerm" {
  alias           = "ims-prd-connectivity"
  subscription_id = "ecd60543-12a0-4899-9e5f-21ec01592207"
  tenant_id       = "684d2402-0ea6-442d-9ad7-4ef26b925ec5"
  client_id       = "74925104-cd8b-47e5-b29a-83a75a2f4ca6"
  features {}
}

provider "azurerm" {
  alias           = "ims-prd-management"
  subscription_id = "b63f4e55-499d-4984-9375-f17853ff6e36"
  tenant_id       = "684d2402-0ea6-442d-9ad7-4ef26b925ec5"
  client_id       = "74925104-cd8b-47e5-b29a-83a75a2f4ca6"
  features {}
}

provider "azurerm" {
  alias           = "ims-prd-avd"
  subscription_id = "9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef"
  tenant_id       = "684d2402-0ea6-442d-9ad7-4ef26b925ec5"
  client_id       = "74925104-cd8b-47e5-b29a-83a75a2f4ca6"
  resource_provider_registrations = "none"
  features {}
}