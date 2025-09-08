terraform {
  backend "azurerm" {
    resource_group_name  = "ims-prd-conn-ne-rg-tfstate"
    storage_account_name = "prdconnalznst"
    container_name       = "tfstate"
    key                  = "connnw.terraform.tfstate" # Path to the state file in the container
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

#########################
# Create nsg on hub vnet
#########################
#1. Create a nsg to associate with "ims-prd-conn-ne-snet-dnsprin" subnet in hub vNet 
  resource "azurerm_network_security_group" "ims-prd-conn-ne-nsg-dnsprin" {
  provider            = azurerm.ims-prd-connectivity
  resource_group_name = "ims-prd-conn-ne-rg-network"
  name                = "ims-prd-conn-ne-nsg-dnsprin"
  location            = "northeurope"

  security_rule {
    direction                     = "Inbound"
    source_address_prefixes       = ["192.168.0.0/22", "192.168.4.0/22", "192.168.8.0/22"]
    source_port_range             = "*"
    destination_address_prefixes  = ["192.168.0.132"]
    destination_port_range        = "53"
    protocol                      = "Tcp"
    access                        = "Allow"
    priority                      = 3000
    name                          = "hub-AllowDNS-TCP-Inbound"
    description                   = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    direction                     = "Inbound"
    source_address_prefixes       = ["192.168.0.0/22", "192.168.4.0/22", "192.168.8.0/22"]
    source_port_range             = "*"
    destination_address_prefixes  = ["192.168.0.132"]
    destination_port_range        = "53"
    protocol                      = "Udp"
    access                        = "Allow"
    priority                      = 3001
    name                          = "hub-AllowDNS-UDP-Inbound"
    description                   = "Allow access to DNS Private Resolver Inbound EP"
  }

  security_rule {
    direction                     = "Inbound"
    source_address_prefix         = "*"
    source_port_range             = "*"
    destination_address_prefix    = "*"
    destination_port_range        = "*"
    protocol                      = "*"
    access                        = "Deny"
    priority                      = 4095
    name                          = "hub-DenyAnyToAnyInbound"
    description                   = "DenyAll"
  }

  security_rule {
    direction                     = "Outbound"
    source_address_prefixes       = ["192.168.0.132"]
    source_port_range             = "*"
    destination_address_prefixes  = ["192.168.0.192/26"]
    destination_port_range        = "53"
    protocol                      = "Tcp"
    access                        = "Allow"
    priority                      = 3000
    name                          = "hub-AllowDNS-TCP-Outbound"
    description                   = "Allow access to DNS Private Resolver Outbound EP"
  }

  security_rule {
    direction                     = "Outbound"
    source_address_prefixes       = ["192.168.0.132"]
    source_port_range             = "*"
    destination_address_prefixes  = ["192.168.0.192/26"]
    destination_port_range        = "53"
    protocol                      = "Udp"
    access                        = "Allow"
    priority                      = 3001
    name                          = "hub-AllowDNS-UDP-Outbound"
    description                   = "Allow access to DNS Private Resolver Outbound EP"
  }

  security_rule {
    direction                     = "Outbound"
    source_address_prefix         = "*"
    source_port_range             = "*"
    destination_address_prefix    = "*"
    destination_port_range        = "*"
    protocol                      = "*"
    access                        = "Deny"
    priority                      = 4095
    name                          = "hub-DenyAnyToAnyOutbound"
    description                   = "DenyAll"
  }

// depends_on = [
//   azurerm_resource_group.ims-prd-conn-ne-rg-network
// ]

    tags = {
    Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.service3}-dnsprin"
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

  # 2. Create a nsg to associate with "ims-prd-conn-ne-snet-dnsprout" subnet in hub vNet
  resource "azurerm_network_security_group" "ims-prd-conn-ne-nsg-dnsprout" {
  provider            = azurerm.ims-prd-connectivity
  resource_group_name = "ims-prd-conn-ne-rg-network"
  name                = "ims-prd-conn-ne-nsg-dnsprout"
  location            = "northeurope"

  security_rule {
    direction                     = "Inbound"
    source_address_prefixes       = ["192.168.0.0/22", "192.168.4.0/22", "192.168.8.0/22"]
    source_port_range             = "*"
    destination_address_prefixes  = ["192.168.0.192/26"]
    destination_port_range        = "53"
    protocol                      = "Tcp"
    access                        = "Allow"
    priority                      = 3000
    name                          = "hub-AllowDNS-TCP-Inbound"
    description                   = "Allow DNS Private Resolver endpoint to receive queries"
    }

  security_rule {
    direction                     = "Inbound"
    source_address_prefixes       = ["192.168.0.0/22", "192.168.4.0/22", "192.168.8.0/22"]
    source_port_range             = "*"
    destination_address_prefixes  = ["192.168.0.192/26"]
    destination_port_range        = "53"
    protocol                      = "Udp"
    access                        = "Allow"
    priority                      = 3001
    name                          = "hub-AllowDNS-UDP-Inbound"
    description                   = "Allow DNS Private Resolver endpoint to receive queries"
    }

  security_rule {
    direction                     = "Inbound"
    source_address_prefix         = "*"
    source_port_range             = "*"
    destination_address_prefix    = "*"
    destination_port_range        = "*"
    protocol                      = "*"
    access                        = "Deny"
    priority                      = 4095
    name                          = "hub-DenyAnyToAnyInbound"
    description                   = "DenyAll"
    }

  security_rule {
    direction                     = "Outbound"
    source_address_prefixes       = ["192.168.0.192/26"]
    source_port_range             = "*"
    destination_address_prefix    = "*"
    destination_port_range        = "53"
    protocol                      = "Tcp"
    access                        = "Allow"
    priority                      = 3000
    name                          = "hub-AllowDNS-TCP-Outbound"
    description                   = "Allow access to DNS Private Resolver Outbound EP"
    }

  security_rule {
    direction                     = "Outbound"
    source_address_prefixes       = ["192.168.0.132"]
    source_port_range             = "*"
    destination_address_prefix    = "*"
    destination_port_range        = "53"
    protocol                      = "Udp"
    access                        = "Allow"
    priority                      = 3001
    name                          = "hub-AllowDNS-UDP-Outbound"
    description                   = "Allow access to DNS Private Resolver Outbound EP"
    }

  security_rule {
    direction                     = "Outbound"
    source_address_prefix         = "*"
    source_port_range             = "*"
    destination_address_prefix    = "*"
    destination_port_range        = "*"
    protocol                      = "*"
    access                        = "Deny"
    priority                      = 4095
    name                          = "hub-DenyAnyToAnyOutbound"
    description                   = "DenyAll"
    }

    # depends_on = [
    #   azurerm_resource_group.ims-prd-conn-ne-rg-network
    # ]

    tags = {
    Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.service3}-dnsprout"
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

#3. Create a nsg to associate with "ims-prd-conn-ne-snet-pep" subnet in hub vNet
  resource "azurerm_network_security_group" "ims-prd-conn-ne-nsg-pep" {
  provider            = azurerm.ims-prd-connectivity
  resource_group_name = "ims-prd-conn-ne-rg-network"
  name                = "ims-prd-conn-ne-nsg-pep"
  location            = "northeurope"

  security_rule {
    direction                     = "Inbound"
    source_address_prefix         = "*"
    source_port_range             = "*"
    destination_address_prefix    = "*"
    destination_port_range        = "*"
    protocol                      = "*"
    access                        = "Deny"
    priority                      = 4095
    name                          = "hub-DenyAnyToAnyInbound"
    description                   = "DenyAll"
    }

  security_rule {
    direction                     = "Outbound"
    source_address_prefix         = "*"
    source_port_range             = "*"
    destination_address_prefix    = "*"
    destination_port_range        = "*"
    protocol                      = "*"
    access                        = "Deny"
    priority                      = 4095
    name                          = "hub-DenyAnyToAnyOutbound"
    description                   = "DenyAll"
    }

    security_rule {
    direction                     = "Outbound"
    source_address_prefix         = "192.168.1.0/26"
    source_port_range             = "*"
    destination_address_prefix    = "192.168.0.132"
    destination_port_range        = "53"
    protocol                      = "Tcp"
    access                        = "Allow"
    priority                      = 3000
    name                          = "hub-AllowDNS-TCP-Outbound"
    description                   = "Allow access to DNS Private Resolver Inbound EP"
    }

    security_rule {
    direction                     = "Outbound"
    source_address_prefix         = "192.168.1.0/26"
    source_port_range             = "*"
    destination_address_prefix    = "192.168.0.132"
    destination_port_range        = "53"
    protocol                      = "Udp"
    access                        = "Allow"
    priority                      = 3001
    name                          = "hub-AllowDNS-UDP-Outbound"
    description                   = "Allow access to DNS Private Resolver Inbound EP"
    }
    # depends_on = [
    #   azurerm_resource_group.ims-prd-conn-ne-rg-network
    # ]

    tags = {
    Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.service3}-pep"
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

#############
# Create UDR 
#############

provider "azurerm" {
  alias           = "ims-prd-connectivity"
  subscription_id = "ecd60543-12a0-4899-9e5f-21ec01592207"
  tenant_id       = "684d2402-0ea6-442d-9ad7-4ef26b925ec5"
  client_id       = "74925104-cd8b-47e5-b29a-83a75a2f4ca6"
  features {}
}

#1. Create a udr to associate with "GatewaySubnet" subnet in hub vNet
resource "azurerm_route_table" "ims-prd-conn-ne-rt-vpng" {
  provider            = azurerm.ims-prd-connectivity
  resource_group_name = "ims-prd-conn-ne-rg-network"
  name                = "ims-prd-conn-ne-rt-vpng"
  location            = "northeurope"
  
  route {
    name                   = "ims-prd-conn-ne-udr-vnet-adv"
    address_prefix         = "192.168.8.0/22"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-conn-ne-udr-vnet-mgmt"
    address_prefix         = "192.168.4.0/22"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-conn-ne-udr-snet-dnsprin"
    address_prefix         = "192.168.0.128/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-conn-ne-udr-snet-dnsprout"
    address_prefix         = "192.168.0.192/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-conn-ne-udr-snet-hubpep"
    address_prefix         = "192.168.1.0/26"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  
  # depends_on = [
  #   azurerm_resource_group.ims-prd-conn-ne-rg-network
  # ]

  tags = {
    Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.service4}-vpng"
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

#2. Create a udr to associate with "ims-prd-conn-ne-snet-dnsprin" subnet subnet in hub vNet
resource "azurerm_route_table" "ims-prd-conn-ne-rt-dnsprin" {
  provider            = azurerm.ims-prd-connectivity
  resource_group_name = "ims-prd-conn-ne-rg-network"
  name                = "ims-prd-conn-ne-rt-dnsprin"
  location            = "northeurope"
  
  route {
    name                   = "default-route"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-conn-ne-udr-vnet-aws"
    address_prefix         = "10.0.0.0/8"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-conn-ne-udr-vnet-avd"
    address_prefix         = "192.168.8.0/22"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-conn-ne-udr-vnet-mgmt"
    address_prefix         = "192.168.4.0/22"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  
  # depends_on = [
  #   azurerm_resource_group.ims-prd-conn-ne-rg-network
  # ]

  tags = {
    Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.service4}-dnsprin"
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


#3. Create a udr to associate with "ims-prd-conn-ne-snet-dnsprout" subnet subnet in hub vNet
resource "azurerm_route_table" "ims-prd-conn-ne-rt-dnsprout" {
  provider            = azurerm.ims-prd-connectivity
  resource_group_name = "ims-prd-conn-ne-rg-network"
  name                = "ims-prd-conn-ne-rt-dnsprout"
  location            = "northeurope"
  
  route {
    name                   = "default-route"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-conn-ne-udr-vnet-aws"
    address_prefix         = "10.0.0.0/8"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-conn-ne-udr-vnet-avd"
    address_prefix         = "192.168.8.0/22"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }
  route {
    name                   = "ims-prd-conn-ne-udr-vnet-mgmt"
    address_prefix         = "192.168.4.0/22"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "192.168.0.68"
  }

  # depends_on = [
  #   azurerm_resource_group.ims-prd-conn-ne-rg-network
  # ]
  
  tags = {
    Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.service4}-dnsprout"
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

###########################################################
# Associate subnets with required NSG and UDR on Hub vNets
###########################################################
# 1. Associate "GatewaySubnet" with "ims-prd-conn-ne-rt-vpng" route table/UDR
resource "azurerm_subnet_route_table_association" "ims-prd-conn-ne-vpng-rt" {
  provider       = azurerm.ims-prd-connectivity
  subnet_id      = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01/subnets/GatewaySubnet"
  route_table_id = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/routeTables/ims-prd-conn-ne-rt-vpng"
}

# 2a. Associate "ims-prd-conn-ne-snet-dnsprin" subnet with "ims-prd-conn-ne-nsg-dnsprin" nsg
resource "azurerm_subnet_network_security_group_association" "ims-prd-conn-ne-dnsprin-nsg" {
  provider                  = azurerm.ims-prd-connectivity
  subnet_id                 = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01/subnets/ims-prd-conn-ne-snet-dnsprin"
  network_security_group_id = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/networkSecurityGroups/ims-prd-conn-ne-nsg-dnsprin"
}

# 2b. Associate "ims-prd-conn-ne-snet-dnsprin" subnet with "ims-prd-conn-ne-rt-dnsprin" route table/UDR
resource "azurerm_subnet_route_table_association" "ims-prd-conn-ne-dnsprin-rt" {
  provider       = azurerm.ims-prd-connectivity
  subnet_id      = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01/subnets/ims-prd-conn-ne-snet-dnsprin"
  route_table_id = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/routeTables/ims-prd-conn-ne-rt-dnsprin"
}
# 3a. Associate "ims-prd-conn-ne-snet-dnsprout" subnet with "ims-prd-conn-ne-nsg-dnsprout" nsg
resource "azurerm_subnet_network_security_group_association" "ims-prd-conn-ne-dnsprout-nsg" {
  provider                  = azurerm.ims-prd-connectivity
  subnet_id                 = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01/subnets/ims-prd-conn-ne-snet-dnsprout"
  network_security_group_id = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/networkSecurityGroups/ims-prd-conn-ne-nsg-dnsprout"
}
# 3b. Associate "ims-prd-conn-ne-snet-dnsprout" subnet with "ims-prd-conn-ne-rt-dnsprout" route table/UDR
resource "azurerm_subnet_route_table_association" "ims-prd-conn-ne-dnsprout-rt" {
  provider       = azurerm.ims-prd-connectivity
  subnet_id      = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01/subnets/ims-prd-conn-ne-snet-dnsprout"
  route_table_id = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/routeTables/ims-prd-conn-ne-rt-dnsprout"
}
# 4. Associate "ims-prd-conn-ne-snet-pep" subnet with "ims-prd-conn-ne-nsg-pep" nsg
resource "azurerm_subnet_network_security_group_association" "ims-prd-conn-ne-pep-nsg" {
  provider                  = azurerm.ims-prd-connectivity
  subnet_id                 = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01/subnets/ims-prd-conn-ne-snet-pep"
  network_security_group_id = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/networkSecurityGroups/ims-prd-conn-ne-nsg-pep"
}
