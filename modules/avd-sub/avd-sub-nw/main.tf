terraform {
  backend "azurerm" {
    resource_group_name  = "ims-prd-lz-ne-rg-terraformstate"
    storage_account_name = "imslandingznstr"
    container_name       = "tfstate"
    key                  = "netrules.terraform.tfstate" # Path to the state file in the container
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

###############################
# Create NSGs on avd vnet
###############################
#1. Create a nsg to associate with "ims-prd-avd-ne-snet-pool" subnet in the avd vNet 
resource "azurerm_network_security_group" "ims-prd-avd-ne-nsg-pool" {
  provider            = azurerm.ims-prd-avd
  resource_group_name = "ims-prd-avd-ne-rg-network"
  location            = "northeurope"
  name                = "ims-prd-avd-ne-nsg-pool"

  security_rule {
    name                       = "avd-DenyAnyToAnyInbound"
    priority                   = 4095
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }

  security_rule {
    name                       = "avd-AllowDNS-TCP-Outbound"
    priority                   = 3000
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "192.168.8.0/24"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "avd-AllowDNS-UDP-Outbound"
    priority                   = 3001
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_address_prefix      = "192.168.8.0/24"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "avd-AllowZscaler-UDP-Outbound"
    priority                   = 3010
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_address_prefix      = "192.168.8.0/24"
    source_port_range          = "*"
    destination_address_prefixes = [
      "147.161.224.0/23", "170.85.58.0/23", "165.225.80.0/22", "147.161.166.0/23",
      "136.226.166.0/23", "136.226.168.0/23", "147.161.140.0/23", "147.161.142.0/23",
      "147.161.144.0/23", "136.226.190.0/23", "147.161.236.0/23", "165.225.196.0/23",
      "165.225.198.0/23", "170.85.84.0/23", "194.9.112.0/23", "194.9.106.0/23",
      "194.9.108.0/23", "194.9.110.0/23", "194.9.114.0/23"
    ]
    destination_port_ranges    = ["80", "443"]
    description                = "Allow AVD access to ZScaler for Internet Access"
  }

  security_rule {
    name                       = "avd-AllowZscaler-TCP-Outbound"
    priority                   = 3011
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "192.168.8.0/24"
    source_port_range          = "*"
    destination_address_prefixes = [
      "147.161.224.0/23", "170.85.58.0/23", "165.225.80.0/22", "147.161.166.0/23",
      "136.226.166.0/23", "136.226.168.0/23", "147.161.140.0/23", "147.161.142.0/23",
      "147.161.144.0/23", "136.226.190.0/23", "147.161.236.0/23", "165.225.196.0/23",
      "165.225.198.0/23", "170.85.84.0/23", "194.9.112.0/23", "194.9.106.0/23",
      "194.9.108.0/23", "194.9.110.0/23", "194.9.114.0/23"
    ]
    destination_port_ranges    = ["80", "443", "9400", "9480", "9443"]
    description                = "Allow AVD access to ZScaler for Internet Access"
  }

  security_rule {
    name                       = "avd-DenyAnyToAnyOutbound"
    priority                   = 4095
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }

  tags = {
    name          = "ims-prd-avd-ne-nsg-pool"
    environment   = "prd"
    function      = "nsg"
    data_creation = "2025-07-21"
  }
  # depends_on = [
  #   azurerm_resource_group.ims-prd-avd-ne-rg-network
  # ]
}

#2. Create a nsg to associate with "ims-prd-avd-ne-snet-personal" subnet in the avd vNet
resource "azurerm_network_security_group" "ims-prd-avd-ne-nsg-personal" {
  provider            = azurerm.ims-prd-avd
  resource_group_name = "ims-prd-avd-ne-rg-network"
  location            = "northeurope"
  name                = "ims-prd-avd-ne-nsg-personal"

  security_rule {
    name                       = "avd-DenyAnyToAnyInbound"
    priority                   = 4095
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }

  security_rule {
    name                       = "avd-AllowDNS-TCP-Outbound"
    priority                   = 3000
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "192.168.9.0/24"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "avd-AllowDNS-UDP-Outbound"
    priority                   = 3001
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_address_prefix      = "192.168.9.0/24"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "avd-AllowZscaler-UDP-Outbound"
    priority                   = 3010
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_address_prefix      = "192.168.9.0/24"
    source_port_range          = "*"
    destination_address_prefixes = [
      "147.161.224.0/23", "170.85.58.0/23", "165.225.80.0/22", "147.161.166.0/23",
      "136.226.166.0/23", "136.226.168.0/23", "147.161.140.0/23", "147.161.142.0/23",
      "147.161.144.0/23", "136.226.190.0/23", "147.161.236.0/23", "165.225.196.0/23",
      "165.225.198.0/23", "170.85.84.0/23", "194.9.112.0/23", "194.9.106.0/23",
      "194.9.108.0/23", "194.9.110.0/23", "194.9.114.0/23"
    ]
    destination_port_ranges    = ["80", "443"]
    description                = "Allow AVD access to ZScaler for Internet Access"
  }

  security_rule {
    name                       = "avd-AllowZscaler-TCP-Outbound"
    priority                   = 3011
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "192.168.9.0/24"
    source_port_range          = "*"
    destination_address_prefixes = [
      "147.161.224.0/23", "170.85.58.0/23", "165.225.80.0/22", "147.161.166.0/23",
      "136.226.166.0/23", "136.226.168.0/23", "147.161.140.0/23", "147.161.142.0/23",
      "147.161.144.0/23", "136.226.190.0/23", "147.161.236.0/23", "165.225.196.0/23",
      "165.225.198.0/23", "170.85.84.0/23", "194.9.112.0/23", "194.9.106.0/23",
      "194.9.108.0/23", "194.9.110.0/23", "194.9.114.0/23"
    ]
    destination_port_ranges    = ["80", "443", "9400", "9480", "9443"]
    description                = "Allow AVD access to ZScaler for Internet Access"
  }

  security_rule {
    name                       = "avd-DenyAnyToAnyOutbound"
    priority                   = 4095
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }

  tags = {
    name          = "ims-prd-avd-ne-nsg-personal"
    environment   = "prd"
    function      = "nsg"
    data_creation = "2025-07-21"
  }
  # depends_on = [
  #   azurerm_resource_group.ims-prd-avd-ne-rg-network
  # ]
}

#3. Create a nsg to associate with "ims-prd-avd-ne-snet-pep" subnet in the avd vNet
resource "azurerm_network_security_group" "ims-prd-avd-ne-nsg-pep" {
  provider            = azurerm.ims-prd-avd
  resource_group_name = "ims-prd-avd-ne-rg-network"
  location            = "northeurope"
  name                = "ims-prd-avd-ne-nsg-pep"

  security_rule {
    name                       = "avd-DenyAnyToAnyInbound"
    priority                   = 4095
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }

  security_rule {
    name                       = "avd-AllowDNS-TCP-Outbound"
    priority                   = 3000
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "192.168.11.128/26"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "avd-AllowDNS-UDP-Outbound"
    priority                   = 3001
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_address_prefix      = "192.168.11.128/26"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "avd-AllowZscaler-UDP-Outbound"
    priority                   = 3010
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_address_prefix      = "192.168.11.128/26"
    source_port_range          = "*"
    destination_address_prefixes = [
      "147.161.224.0/23", "170.85.58.0/23", "165.225.80.0/22", "147.161.166.0/23",
      "136.226.166.0/23", "136.226.168.0/23", "147.161.140.0/23", "147.161.142.0/23",
      "147.161.144.0/23", "136.226.190.0/23", "147.161.236.0/23", "165.225.196.0/23",
      "165.225.198.0/23", "170.85.84.0/23", "194.9.112.0/23", "194.9.106.0/23",
      "194.9.108.0/23", "194.9.110.0/23", "194.9.114.0/23"
    ]
    destination_port_ranges    = ["80", "443"]
    description                = "Allow AVD access to ZScaler for Internet Access"
  }

  security_rule {
    name                       = "avd-AllowZscaler-TCP-Outbound"
    priority                   = 3011
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "192.168.11.128/26"
    source_port_range          = "*"
    destination_address_prefixes = [
      "147.161.224.0/23", "170.85.58.0/23", "165.225.80.0/22", "147.161.166.0/23",
      "136.226.166.0/23", "136.226.168.0/23", "147.161.140.0/23", "147.161.142.0/23",
      "147.161.144.0/23", "136.226.190.0/23", "147.161.236.0/23", "165.225.196.0/23",
      "165.225.198.0/23", "170.85.84.0/23", "194.9.112.0/23", "194.9.106.0/23",
      "194.9.108.0/23", "194.9.110.0/23", "194.9.114.0/23"
    ]
    destination_port_ranges    = ["80", "443", "9400", "9480", "9443"]
    description                = "Allow AVD access to ZScaler for Internet Access"
  }

  security_rule {
    name                       = "avd-DenyAnyToAnyOutbound"
    priority                   = 4095
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }

  tags = {
    name          = "ims-prd-avd-ne-nsg-pep"
    environment   = "prd"
    function      = "nsg"
    data_creation = "2025-07-21"
  }
  # depends_on = [
  #   azurerm_resource_group.ims-prd-avd-ne-rg-network
  # ]
}
resource "azurerm_network_security_group" "ims-prd-avd-ne-nsg-mgmt" {
  provider            = azurerm.ims-prd-avd
  resource_group_name = "ims-prd-avd-ne-rg-network"
  location            = "northeurope"
  name                = "ims-prd-avd-ne-nsg-mgmt"

  security_rule {
    name                       = "avd-AllowMgmt-TCP-Outbound"
    priority                   = 3000
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "192.168.10.0/24"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.68"
    destination_port_ranges    = ["443", "1688", "80"]
  }

  security_rule {
    name                       = "avd-AllowMgmt-UDP-Outbound"
    priority                   = 3001
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_address_prefix      = "192.168.10.0/24"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.68"
    destination_port_range     = "3390"
  }

  security_rule {
    name                       = "avd-DenyAnyToAnyInbound"
    priority                   = 4095
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }
  security_rule {
    name                       = "avd-DenyAnyToAnyOutbound"
    priority                   = 4095
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }
    tags = {
    name          = "ims-prd-avd-ne-nsg-mgmt"
    environment   = "prd"
    function      = "nsg"
    data_creation = "2025-07-21"
  }
  # depends_on = [
  #   azurerm_resource_group.ims-prd-avd-ne-rg-network
  # ]
}
###############################
# Create UDRs
###############################
#1. Create a udr to associate with "ims-prd-avd-ne-snet-pool" subnet in the avd vNet
resource "azurerm_route_table" "ims-prd-avd-ne-rt-pool" {
  provider            = azurerm.ims-prd-avd
  resource_group_name = "ims-prd-avd-ne-rg-network"
  location            = "northeurope"
  name                = "ims-prd-avd-ne-rt-pool"

  route {
    name                   = "defaultRoute"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-avd-ne-udr-vnet-aws"
    address_prefix         = "10.0.0.0/8"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-avd-ne-udr-vnet-mgmt"
    address_prefix         = "192.168.4.0/22"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-avd-ne-udr-snet-dnsprin"
    address_prefix         = "192.168.0.128/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-avd-ne-udr-snet-hubpep"
    address_prefix         = "192.168.1.0/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }

  tags = {
    name          = "ims-prd-avd-ne-rt-pool"
    environment   = "prd"
    function      = "route table"
    data_creation = "2025-07-21"
  }
  # depends_on = [
  #   azurerm_resource_group.ims-prd-avd-ne-rg-network
  # ]
}

#2. Create a udr to associate with "ims-prd-avd-ne-snet-personal" subnet in the avd vNet
resource "azurerm_route_table" "ims-prd-avd-ne-rt-personal" {
  provider            = azurerm.ims-prd-avd
  resource_group_name = "ims-prd-avd-ne-rg-network"
  location            = "northeurope"
  name                = "ims-prd-avd-ne-rt-personal"

  route {
    name                   = "defaultRoute"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-avd-ne-udr-vnet-aws"
    address_prefix         = "10.0.0.0/8"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-avd-ne-udr-vnet-mgmt"
    address_prefix         = "192.168.4.0/22"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-avd-ne-udr-snet-dnsprin"
    address_prefix         = "192.168.0.128/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-avd-ne-udr-snet-hubpep"
    address_prefix         = "192.168.1.0/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }

  tags = {
    name          = "ims-prd-avd-ne-rt-personal"
    environment   = "prd"
    function      = "route table"
    data_creation = "2025-07-21"
  }
  # depends_on = [
  #   azurerm_resource_group.ims-prd-avd-ne-rg-network
  # ]
}

#3. Create a udr to associate with "ims-prd-avd-ne-rt-mgmt" subnet in the avd vNet
resource "azurerm_route_table" "ims-prd-avd-ne-rt-mgmt" {
  provider            = azurerm.ims-prd-avd
  resource_group_name = "ims-prd-avd-ne-rg-network"
  location            = "northeurope"
  name                = "ims-prd-avd-ne-rt-mgmt"

  route {
    name                   = "defaultRoute"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }

  route {
    name                   = "ims-prd-avd-ne-udr-vnet-aws"
    address_prefix         = "10.0.0.0/8"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }

  route {
    name                   = "ims-prd-avd-ne-udr-vnet-mgmt"
    address_prefix         = "192.168.4.0/22"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }

  route {
    name                   = "ims-prd-avd-ne-udr-snet-dnsprin"
    address_prefix         = "192.168.0.128/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }

  route {
    name                   = "ims-prd-avd-ne-udr-snet-hubpep"
    address_prefix         = "192.168.1.0/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }

}

################################################################
# Associate subnets with required NSG and UDR on Avd vNets
################################################################
# 1a. Associate "ims-prd-avd-ne-snet-pool" subnet with "ims-prd-avd-ne-snet-nsg-pool" nsg
resource "azurerm_subnet_network_security_group_association" "ims-prd-avd-ne-snet-pool-nsg" {
  provider                  = azurerm.ims-prd-avd
  subnet_id                 = "/subscriptions/9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef/resourceGroups/ims-prd-avd-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-avd-ne-vnet-01/subnets/ims-prd-avd-ne-snet-pool"
  network_security_group_id = "/subscriptions/9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef/resourceGroups/ims-prd-avd-ne-rg-network/providers/Microsoft.Network/networkSecurityGroups/ims-prd-avd-ne-nsg-pool"

}
# 1b. Associate "ims-prd-avd-ne-snet-pool" subnet with "ims-prd-avd-ne-snet-rt-pool" route table/UDR
resource "azurerm_subnet_route_table_association" "ims-prd-avd-ne-snet-pool-rt" {
  provider       = azurerm.ims-prd-avd
  subnet_id      = "/subscriptions/9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef/resourceGroups/ims-prd-avd-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-avd-ne-vnet-01/subnets/ims-prd-avd-ne-snet-pool"
  route_table_id = "/subscriptions/9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef/resourceGroups/ims-prd-avd-ne-rg-network/providers/Microsoft.Network/routeTables/ims-prd-avd-ne-rt-pool"

}
# 2a. Associate "ims-prd-avd-ne-snet-personal" subnet with "ims-prd-avd-ne-snet-nsg-personal" nsg
resource "azurerm_subnet_network_security_group_association" "ims-prd-avd-ne-snet-personal-nsg" {
  provider                  = azurerm.ims-prd-avd
  subnet_id                 = "/subscriptions/9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef/resourceGroups/ims-prd-avd-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-avd-ne-vnet-01/subnets/ims-prd-avd-ne-snet-personal"
  network_security_group_id = "/subscriptions/9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef/resourceGroups/ims-prd-avd-ne-rg-network/providers/Microsoft.Network/networkSecurityGroups/ims-prd-avd-ne-nsg-personal"

}
# 2b. Associate "ims-prd-avd-ne-snet-personal" subnet with "ims-prd-avd-ne-snet-rt-personal" route table/UDR
resource "azurerm_subnet_route_table_association" "ims-prd-avd-ne-snet-personal-rt" {
  provider       = azurerm.ims-prd-avd
  subnet_id      = "/subscriptions/9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef/resourceGroups/ims-prd-avd-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-avd-ne-vnet-01/subnets/ims-prd-avd-ne-snet-personal"
  route_table_id = "/subscriptions/9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef/resourceGroups/ims-prd-avd-ne-rg-network/providers/Microsoft.Network/routeTables/ims-prd-avd-ne-rt-personal"

}
# 3. Associate "ims-prd-avd-ne-snet-pep" subnet with "ims-prd-avd-ne-snet-nsg-pep" nsg
resource "azurerm_subnet_network_security_group_association" "ims-prd-avd-ne-snet-pep-nsg" {
  provider                  = azurerm.ims-prd-avd
  subnet_id                 = "/subscriptions/9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef/resourceGroups/ims-prd-avd-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-avd-ne-vnet-01/subnets/ims-prd-avd-ne-snet-pep"
  network_security_group_id = "/subscriptions/9da3ee14-3ae9-4be0-9ad2-b9a7c7b059ef/resourceGroups/ims-prd-avd-ne-rg-network/providers/Microsoft.Network/networkSecurityGroups/ims-prd-avd-ne-nsg-pep"

}