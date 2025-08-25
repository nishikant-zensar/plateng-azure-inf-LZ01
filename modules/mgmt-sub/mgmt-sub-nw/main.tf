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
# Create NSGs on mgmt vnet
###############################
#1. Create a nsg to associate with "ims-prd-mgmt-ne-snet-security" subnet in the mgmt vNet 
resource "azurerm_network_security_group" "ims-prd-mgmt-ne-nsg-security" {
  provider            = azurerm.ims-prd-management
  resource_group_name = "ims-prd-mgmt-ne-rg-network"
  name                = "ims-prd-mgmt-ne-nsg-security"
  location            = "northeurope"

  security_rule {
    name                       = "mgmt-DenyAnyToAnyInbound"
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
    name                       = "mgmt-AllowDNS-TCP-Outbound"
    priority                   = 3000
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "192.168.4.0/26"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "mgmt-AllowDNS-UDP-Outbound"
    priority                   = 3001
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_address_prefix      = "192.168.4.0/26"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "mgmt-DenyAnyToAnyOutbound"
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
    name          = "ims-prd-mgmt-ne-nsg-security"
    environment   = "prd"
    function      = "nsg"
    data_creation = "2025-07-21"
  }

  # depends_on = [
  #   azurerm_resource_group.ims-prd-mgmt-ne-rg-network
  # ]
}

#2. Create a nsg to associate with "ims-prd-mgmt-ne-snet-system" subnet in the mgmt vNet 
resource "azurerm_network_security_group" "ims-prd-mgmt-ne-nsg-system" {
  provider            = azurerm.ims-prd-management
  resource_group_name = "ims-prd-mgmt-ne-rg-network"
  location            = "northeurope"
  name                = "ims-prd-mgmt-ne-nsg-system"

  security_rule {
    name                       = "mgmt-DenyAnyToAnyInbound"
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
    name                       = "mgmt-AllowDNS-TCP-Outbound"
    priority                   = 3000
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "192.168.4.64/26"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "mgmt-AllowDNS-UDP-Outbound"
    priority                   = 3001
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_address_prefix      = "192.168.4.64/26"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "mgmt-DenyAnyToAnyOutbound"
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
    name          = "ims-prd-mgmt-ne-nsg-system"
    environment   = "prd"
    function      = "nsg"
    data_creation = "2025-07-21"
  }

  # depends_on = [
  #   azurerm_resource_group.ims-prd-mgmt-ne-rg-network
  # ]
}

#3. Create a nsg to associate with "ims-prd-mgmt-ne-snet-keyvault" subnet in the mgmt vNet 
resource "azurerm_network_security_group" "ims-prd-mgmt-ne-nsg-keyvault" {
  provider            = azurerm.ims-prd-management
  resource_group_name = "ims-prd-mgmt-ne-rg-network"
  location            = "northeurope"
  name                = "ims-prd-mgmt-ne-nsg-keyvault"

  security_rule {
    name                       = "mgmt-DenyAnyToAnyInbound"
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
    name                       = "mgmt-AllowDNS-TCP-Outbound"
    priority                   = 3000
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "192.168.4.128/26"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "mgmt-AllowDNS-UDP-Outbound"
    priority                   = 3001
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_address_prefix      = "192.168.4.128/26"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "mgmt-DenyAnyToAnyOutbound"
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
    name          = "ims-prd-mgmt-ne-nsg-keyvault"
    environment   = "prd"
    function      = "nsg"
    data_creation = "2025-07-21"
  }
  #  depends_on = [
  #   azurerm_resource_group.ims-prd-mgmt-ne-rg-network
  # ]
}

#4. Create a nsg to associate with "ims-prd-mgmt-ne-snet-pep" subnet in the mgmt vNet
resource "azurerm_network_security_group" "ims-prd-mgmt-ne-nsg-pep" {
  provider            = azurerm.ims-prd-management
  resource_group_name = "ims-prd-mgmt-ne-rg-network"
  location            = "northeurope"
  name                = "ims-prd-mgmt-ne-nsg-pep"

  security_rule {
    name                       = "mgmt-DenyAnyToAnyInbound"
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
    name                       = "mgmt-AllowDNS-TCP-Outbound"
    priority                   = 3000
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "192.168.4.192/26"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "mgmt-AllowDNS-UDP-Outbound"
    priority                   = 3001
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_address_prefix      = "192.168.4.192/26"
    source_port_range          = "*"
    destination_address_prefix = "192.168.0.132"
    destination_port_range     = "53"
    description                = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    name                       = "mgmt-DenyAnyToAnyOutbound"
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
    name          = "ims-prd-mgmt-ne-nsg-pep"
    environment   = "prd"
    function      = "nsg"
    data_creation = "2025-07-21"
  }
  #  depends_on = [
  #   azurerm_resource_group.ims-prd-mgmt-ne-rg-network
  # ]
}
###############################
# Create UDRs
###############################
#1. Create a udr to associate with "ims-prd-mgmt-ne-snet-keyvault" subnet in the mgmt vNet
resource "azurerm_route_table" "ims-prd-mgmt-ne-rt-keyvault" {
  provider            = azurerm.ims-prd-management
  resource_group_name = "ims-prd-mgmt-ne-rg-network"
  location            = "northeurope"
  name                = "ims-prd-mgmt-ne-rt-keyvault"

  route {
    name                   = "defaultRoute"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-mgmt-ne-udr-vnet-avd"
    address_prefix         = "192.168.8.0/22"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-mgmt-ne-udr-snet-dnsprin"
    address_prefix         = "192.168.0.128/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-mgmt-ne-udr-snet-vpng"
    address_prefix         = "192.168.0.0/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }

  tags = {
    name          = "ims-prd-mgmt-ne-rt-keyvault"
    environment   = "prd"
    function      = "route table"
    data_creation = "2025-07-21"
  }
  # depends_on = [
  #   azurerm_resource_group.ims-prd-mgmt-ne-rg-network
  # ]
}

#2. Create a udr to associate with "ims-prd-mgmt-ne-snet-security" subnet in the mgmt vNet
resource "azurerm_route_table" "ims-prd-mgmt-ne-rt-security" {
  provider            = azurerm.ims-prd-management
  resource_group_name = "ims-prd-mgmt-ne-rg-network"
  location            = "northeurope"
  name                = "ims-prd-mgmt-ne-rt-security"

  route {
    name                   = "defaultRoute"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-mgmt-ne-udr-vnet-avd"
    address_prefix         = "192.168.8.0/22"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-mgmt-ne-udr-snet-dnsprin"
    address_prefix         = "192.168.0.128/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-mgmt-ne-udr-snet-vpng"
    address_prefix         = "192.168.0.0/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }

  tags = {
    name          = "ims-prd-mgmt-ne-rt-security"
    environment   = "prd"
    function      = "route table"
    data_creation = "2025-07-21"
  }
  # depends_on = [
  #   azurerm_resource_group.ims-prd-mgmt-ne-rg-network
  # ]
}

#3. Create a udr to associate with "ims-prd-mgmt-ne-snet-system" subnet in the mgmt vNet
resource "azurerm_route_table" "ims-prd-mgmt-ne-rt-system" {
  provider            = azurerm.ims-prd-management
  resource_group_name = "ims-prd-mgmt-ne-rg-network"
  location            = "northeurope"
  name                = "ims-prd-mgmt-ne-rt-system"

  route {
    name                   = "defaultRoute"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-mgmt-ne-udr-vnet-avd"
    address_prefix         = "192.168.8.0/22"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-mgmt-ne-udr-snet-dnsprin"
    address_prefix         = "192.168.0.128/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-mgmt-ne-udr-snet-vpng"
    address_prefix         = "192.168.0.0/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }

  tags = {
    name          = "ims-prd-mgmt-ne-rt-system"
    environment   = "prd"
    function      = "route table"
    data_creation = "2025-07-21"
  }
  # depends_on = [
  #   azurerm_resource_group.ims-prd-mgmt-ne-rg-network
  # ]
}

################################################################
# Associate subnets with required NSG and UDR on Mgmt vNets
################################################################
# 1a. Associate "ims-prd-mgmt-ne-snet-security" subnet with "ims-prd-mgmt-ne-snet-nsg-security" nsg
resource "azurerm_subnet_network_security_group_association" "ims-prd-mgmt-ne-snet-security-nsg" {
  provider                  = azurerm.ims-prd-management
  subnet_id                 = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-mgmt-ne-vnet-01/subnets/ims-prd-mgmt-ne-snet-security"
  network_security_group_id = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/networkSecurityGroups/ims-prd-mgmt-ne-nsg-security"
  
}
# 1b. Associate "ims-prd-mgmt-ne-snet-security" subnet with "ims-prd-mgmt-ne-snet-rt-security" route table/UDR
resource "azurerm_subnet_route_table_association" "ims-prd-mgmt-ne-snet-security-rt" {
  provider       = azurerm.ims-prd-management
  subnet_id      = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-mgmt-ne-vnet-01/subnets/ims-prd-mgmt-ne-snet-security"
  route_table_id = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/routeTables/ims-prd-mgmt-ne-rt-security"
  
}
# 2a. Associate "ims-prd-mgmt-ne-snet-system" subnet with "ims-prd-mgmt-ne-snet-nsg-system" nsg
resource "azurerm_subnet_network_security_group_association" "ims-prd-mgmt-ne-snet-system-nsg" {
  provider                  = azurerm.ims-prd-management
  subnet_id                 = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-mgmt-ne-vnet-01/subnets/ims-prd-mgmt-ne-snet-system"
  network_security_group_id = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/networkSecurityGroups/ims-prd-mgmt-ne-nsg-system"
   
}
# 2b. Associate "ims-prd-mgmt-ne-snet-system" subnet with "ims-prd-mgmt-ne-snet-rt-system" route table/UDR
resource "azurerm_subnet_route_table_association" "ims-prd-mgmt-ne-snet-system-rt" {
  provider       = azurerm.ims-prd-management
  subnet_id      = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-mgmt-ne-vnet-01/subnets/ims-prd-mgmt-ne-snet-system"
  route_table_id = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/routeTables/ims-prd-mgmt-ne-rt-system"
  
}
# 3a. Associate "ims-prd-mgmt-ne-snet-keyvault" subnet with "ims-prd-mgmt-ne-snet-nsg-keyvault" nsg
resource "azurerm_subnet_network_security_group_association" "ims-prd-mgmt-ne-snet-keyvault-nsg" {
  provider                  = azurerm.ims-prd-management
  subnet_id                 = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-mgmt-ne-vnet-01/subnets/ims-prd-mgmt-ne-snet-keyvault"
  network_security_group_id = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/networkSecurityGroups/ims-prd-mgmt-ne-nsg-keyvault"

}
# 3b. Associate "ims-prd-mgmt-ne-snet-keyvault" subnet with "ims-prd-mgmt-ne-snet-rt-keyvault" route table/UDR
resource "azurerm_subnet_route_table_association" "ims-prd-mgmt-ne-snet-keyvault-rt" {
  provider       = azurerm.ims-prd-management
  subnet_id      = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-mgmt-ne-vnet-01/subnets/ims-prd-mgmt-ne-snet-keyvault"
  route_table_id = "/subscriptions/b63f4e55-499d-4984-9375-f17853ff6e36/resourceGroups/ims-prd-mgmt-ne-rg-network/providers/Microsoft.Network/routeTables/ims-prd-mgmt-ne-rt-keyvault"

}