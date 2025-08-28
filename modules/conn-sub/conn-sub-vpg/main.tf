terraform {
  backend "azurerm" {
    resource_group_name  = "ims-prd-conn-ne-rg-tfstate"
    storage_account_name = "prdconnalznst"
    container_name       = "tfstate"
    key                  = "connvpg.terraform.tfstate" # Path to the state file in the container
    use_oidc_auth        = true
    use_azuread_auth     = true
  }
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.36"
    }
  }
  required_version = ">= 1.9, < 2.0"
}

#################################
# Create Public IP's for Gateway
#################################
# 1. Create "ims-prd-conn-ne-pip-vpng-01" Public IP for VPN Gateway

resource "azurerm_public_ip" "pipvpng01" {
  name                = "ims-prd-conn-ne-pip-vpng-01"
  resource_group_name = var.vnet_resource_group
  location            = var.location
  sku                 = var.sku
  allocation_method   = var.allocation_method
  ip_version          = var.ip_version
  zones               = ["1"]
  # tier                = var.tier
  domain_name_label   = var.domain_name_label
  idle_timeout_in_minutes = var.idle_timeout_in_minutes
  # ip_protection_mode  = "Enabled"

  # Routing Preference (Internet, Microsoft), only valid for Standard SKU with IPv4
  # routing_preference = var.routing_preference

  # DDoS protection is only available for Standard SKU
  # ddos_protection_mode = var.ddos_protection_mode

  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.service2}-vpng-01"
	Environment = var.env
	DateCreated = formatdate("YYYY-MM-DD", timestamp())
  }
}
# 2. Create "ims-prd-conn-ne-pip-vpng-02" Public IP for VPN Gateway

resource "azurerm_public_ip" "pipvpng02" {
  name                = "ims-prd-conn-ne-pip-vpng-02"
  resource_group_name = var.vnet_resource_group
  location            = var.location
  sku                 = var.sku
  allocation_method   = var.allocation_method
  ip_version          = var.ip_version
  zones               = ["1"]
  # tier                = var.tier
  domain_name_label   = var.domain_name_label
  idle_timeout_in_minutes = var.idle_timeout_in_minutes
  # ip_protection_mode = "Enabled"

  # Routing Preference (Internet, Microsoft), only valid for Standard SKU with IPv4
  # routing_preference = var.routing_preference

  # DDoS protection is only available for Standard SKU
  # ddos_protection_mode = var.ddos_protection_mode
  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.service2}-vpng-02"
	Environment = var.env
	DateCreated = formatdate("YYYY-MM-DD", timestamp())
  }
}

############################################################
# Create Virtual Private Gateway and Local Network Gateways
############################################################
# 1. Create ims-prd-conn-ne-vpng-01 VPN Gateway

resource "azurerm_virtual_network_gateway" "vpn_gw" {
  # subscription        = var.connectivity_subscription_id
  name                = "ims-prd-conn-ne-vpng-01"
  location            = var.location
  resource_group_name = var.vnet_resource_group

  type     = "Vpn"
  vpn_type = "RouteBased"
  sku      = "VpnGw2AZ"
  generation = "Generation2"

  active_active = true

  ip_configuration {
    name                          = "vpng-ipconfig1"
    public_ip_address_id          = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/publicIPAddresses/ims-prd-conn-ne-pip-vpng-01"
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01/subnets/GatewaySubnet"
  }

  ip_configuration {
    name                          = "vpng-ipconfig2"
    public_ip_address_id          = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/publicIPAddresses/ims-prd-conn-ne-pip-vpng-02"
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01/subnets/GatewaySubnet"
  }

  enable_bgp    = true
  bgp_settings {
    asn = 65515

    peering_addresses {
      ip_configuration_name   = "vpng-ipconfig1"
      apipa_addresses         = ["169.254.21.22", "169.254.21.6"]
      # default_bgp_ip_addresses = ["192.168.0.4"]
      # tunnel_ip_addresses      = []
    }

    peering_addresses {
      ip_configuration_name   = "vpng-ipconfig2"
      apipa_addresses         = ["169.254.22.22", "169.254.22.6"]
      # default_bgp_ip_addresses = ["192.168.0.5"]
      # tunnel_ip_addresses      = []
    }
  }

  # Key Vault Access, Managed Identity, and Authentication Information (preview) not enabled.
  
  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-vpng-01"
	Environment = var.env
	DateCreated = formatdate("YYYY-MM-DD", timestamp())
  }
}
# 2. Create Local Network Gateway 1 on VPN Gateway

resource "azurerm_local_network_gateway" "aws_lgw1" {
  name                = "ims-prd-conn-ne-lgw-aws-01"
  location            = var.location
  resource_group_name = var.vnet_resource_group
  gateway_address     = "34.247.16.167"
  address_space       = ["10.0.0.0/14"]
  bgp_settings {
    asn           = 64512
    bgp_peering_address = "169.254.21.21"
    peer_weight   = 0
  }
}

# 3. Create Local Network Gateway 2 on VPN Gateway
resource "azurerm_local_network_gateway" "aws_lgw2" {
  name                = "ims-prd-conn-ne-lgw-aws-02"
  location            = var.location
  resource_group_name = var.vnet_resource_group
  gateway_address     = "99.81.84.117"
  address_space       = ["10.0.0.0/14"]
  bgp_settings {
    asn           = 64512
    bgp_peering_address = "169.254.22.21"
    peer_weight   = 0
  }
}

# 4. Create Local Network Gateway 3 on VPN Gateway
resource "azurerm_local_network_gateway" "aws_lgw3" {
  name                = "ims-prd-conn-ne-lgw-aws-03"
  location            = var.location
  resource_group_name = var.vnet_resource_group
  gateway_address     = "52.51.99.83"
  address_space       = ["10.0.0.0/14"]
  bgp_settings {
    asn           = 64512
    bgp_peering_address = "169.254.21.5"
    peer_weight   = 0
  }
}

# 5. Create Local Network Gateway 4 on VPN Gateway
resource "azurerm_local_network_gateway" "aws_lgw4" {
  name                = "ims-prd-conn-ne-lgw-aws-04"
  location            = var.location
  resource_group_name = var.vnet_resource_group
  gateway_address     = "52.213.133.44"
  address_space       = ["10.0.0.0/14"]
  bgp_settings {
    asn           = 64512
    bgp_peering_address = "169.254.22.5"
    peer_weight   = 0
  }
}

# 6. Create Gateway Connection 1 on VPN Gateway

# resource "azurerm_virtual_network_gateway_connection" "s2s_connection1" {
#  name                            = "ims-prd-conn-ne-vnc-01"
#  location                        = var.location
#  resource_group_name             = var.vnet_resource_group
#  type                            = "IPsec"
#  virtual_network_gateway_id      = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworkGateways/ims-prd-conn-ne-vpng-01"
#  local_network_gateway_id        = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/localNetworkGateways/ims-prd-conn-ne-lgw-aws-01"
#  connection_protocol             = "IKEv2"
#  shared_key                      = "B8Ef._xcfBMoggqRgHpVXRocAXq3ejDX" # Replace with your actual pre-shared key
#  dpd_timeout_seconds             = 45
#  use_policy_based_traffic_selectors = true

  # IPsec/IKE policy is default (no custom policy block)
  # NAT Rules not configured

 # tags = {
 # Name = "${var.org}-${var.env}-${var.sub}-${var.region}-vnc-01"
#	Environment = var.env
#	DateCreated = formatdate("YYYY-MM-DD", timestamp())
 # }

#}
# 7. Create Gateway Connection 2 on VPN Gateway

#resource "azurerm_virtual_network_gateway_connection" "s2s_connection2" {
#  name                            = "ims-prd-conn-ne-vnc-02"
#  location                        = var.location
#  resource_group_name             = var.vnet_resource_group
#  type                            = "IPsec"
#  virtual_network_gateway_id      = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworkGateways/ims-prd-conn-ne-vpng-01"
#  local_network_gateway_id        = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/localNetworkGateways/ims-prd-conn-ne-lgw-aws-02"
#  connection_protocol             = "IKEv2"
#  shared_key                      = "gyRTAP4mgsUbmTcTqJBQCU02ChqzRvSX" # Replace with your actual pre-shared key
#  dpd_timeout_seconds             = 45
#  use_policy_based_traffic_selectors = true

  # IPsec/IKE policy is default (no custom policy block)
  # NAT Rules not configured

 # tags = {
 # Name = "${var.org}-${var.env}-${var.sub}-${var.region}-vnc-02"
#	Environment = var.env
#	DateCreated = formatdate("YYYY-MM-DD", timestamp())
 # }
# }

# 8. Create Gateway Connection 3 on VPN Gateway

#resource "azurerm_virtual_network_gateway_connection" "s2s_connection3" {
#  name                            = "ims-prd-conn-ne-vnc-03"
#  location                        = var.location
#  resource_group_name             = var.vnet_resource_group
#  type                            = "IPsec"
#  virtual_network_gateway_id      = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworkGateways/ims-prd-conn-ne-vpng-01"
#  local_network_gateway_id        = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/localNetworkGateways/ims-prd-conn-ne-lgw-aws-02"
#  connection_protocol             = "IKEv2"
#  shared_key                      = "gyRTAP4mgsUbmTcTqJBQCU02ChqzRvSX" # Replace with your actual pre-shared key
#  dpd_timeout_seconds             = 45
#  use_policy_based_traffic_selectors = true

  # IPsec/IKE policy is default (no custom policy block)
  # NAT Rules not configured

 # tags = {
 # Name = "${var.org}-${var.env}-${var.sub}-${var.region}-vnc-03"
#	Environment = var.env
#	DateCreated = formatdate("YYYY-MM-DD", timestamp())
 # }
# }

# 9. Create Gateway Connection 4 on VPN Gateway

#resource "azurerm_virtual_network_gateway_connection" "s2s_connection4" {
#  name                            = "ims-prd-conn-ne-vnc-04"
#  location                        = var.location
#  resource_group_name             = var.vnet_resource_group
#  type                            = "IPsec"
#  virtual_network_gateway_id      = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworkGateways/ims-prd-conn-ne-vpng-01"
#  local_network_gateway_id        = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/localNetworkGateways/ims-prd-conn-ne-lgw-aws-02"
#  connection_protocol             = "IKEv2"
#  shared_key                      = "gyRTAP4mgsUbmTcTqJBQCU02ChqzRvSX" # Replace with your actual pre-shared key
#  dpd_timeout_seconds             = 45
#  use_policy_based_traffic_selectors = true

  # IPsec/IKE policy is default (no custom policy block)
  # NAT Rules not configured

 # tags = {
 # Name = "${var.org}-${var.env}-${var.sub}-${var.region}-vnc-04"
#	Environment = var.env
#	DateCreated = formatdate("YYYY-MM-DD", timestamp())
 # }
# }
