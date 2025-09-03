terraform {
  backend "azurerm" {
    resource_group_name  = "ims-prd-conn-ne-rg-tfstate"
    storage_account_name = "prdconnalznst"
    container_name       = "tfstate"
    key                  = "connfw.terraform.tfstate" # Path to the state file in the container
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

################################
# Create Public IP for Firewall
################################
# Create "ims-prd-conn-ne-pip-afw-01" Public IP for Firewall

resource "azurerm_public_ip" "pipafw01" {
  name                = "ims-prd-conn-ne-pip-afw-01"
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
  # tags = {
   # Name          = "ims-prd-conn-ne-pip-afw-01"
   # Environment   = "prd"
   # DateCreated   = "2025-08-01"
  # }
  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.service2}-${var.azfw}-01"
	Environment = var.env
	DateCreated = formatdate("YYYY-MM-DD", timestamp())
  }

}

##################
# Create IP Groups
##################
# 1. Create IP Group for Zscaller IP Groups at London 3
resource "azurerm_ip_group" "ims-prd-conn-ne-ZscallerIPg-L3" {
  provider            = azurerm.ims-prd-connectivity
  name                = "ims-prd-conn-ne-ZscallerIPg-L3"
  resource_group_name = "ims-prd-conn-ne-rg-network"
  location            = "northeurope"

  cidrs = [
    "147.161.224.0/23", "170.85.58.0/23", "165.225.80.0/22", "147.161.166.0/23"
  ]

  depends_on = [
    azurerm_resource_group.ims-prd-conn-ne-rg-network
  ]

  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.ipg}-L3"
	Environment = var.env
	DateCreated = formatdate("YYYY-MM-DD", timestamp())
  }
}

# 2. Create IP Group for Zscaller IP Groups at London 5
resource "azurerm_ip_group" "ims-prd-conn-ne-ZscallerIPg-L5" {
  provider            = azurerm.ims-prd-connectivity
  name                = "ims-prd-conn-ne-ZscallerIPg-L5"
  resource_group_name = "ims-prd-conn-ne-rg-network"
  location            = "northeurope"

  cidrs = [
    "136.226.166.0/23", "136.226.168.0/23", "147.161.140.0/23", "147.161.142.0/23", "147.161.144.0/23"
  ]

  depends_on = [
    azurerm_resource_group.ims-prd-conn-ne-rg-network
  ]
  
  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.ipg}-L5"
	Environment = var.env
	DateCreated = formatdate("YYYY-MM-DD", timestamp())
  }
}

# 3. Create IP Group for Zscaller IP Groups at Manchester 1
resource "azurerm_ip_group" "ims-prd-conn-ne-ZscallerIPg-M1" {
  provider            = azurerm.ims-prd-connectivity
  name                = "ims-prd-conn-ne-ZscallerIPg-M1"
  resource_group_name = "ims-prd-conn-ne-rg-network"
  location            = "northeurope"

  cidrs = [
    "136.226.190.0/23", "147.161.236.0/23", "165.225.196.0/23", "165.255.198.0/23", "170.85.84.0/23"
  ]

  depends_on = [
    azurerm_resource_group.ims-prd-conn-ne-rg-network
  ]

  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.ipg}-M1"
	Environment = var.env
	DateCreated = formatdate("YYYY-MM-DD", timestamp())
  }
  
}
# 4. Create IP Group for Zscaller IP Groups at Manchester 2
resource "azurerm_ip_group" "ims-prd-conn-ne-ZscallerIPg-M2" {
  provider            = azurerm.ims-prd-connectivity
  name                = "ims-prd-conn-ne-ZscallerIPg-M2"
  resource_group_name = "ims-prd-conn-ne-rg-network"
  location            = "northeurope"

  cidrs = [
    "194.9.122.0/23", "194.9.106.0/23", "194.9.108.0/23", "194.9.110.0/23", "194.9.114.0/23"
  ]

  depends_on = [
    azurerm_resource_group.ims-prd-conn-ne-rg-network
  ]

  tags = {
  Name = "${var.org}-${var.env}-${var.sub}-${var.region}-${var.ipg}-M2"
	Environment = var.env
	DateCreated = formatdate("YYYY-MM-DD", timestamp())
  }
}

##############################################
# Create Azure Firewall and Firewall Policies
##############################################

# 1. Create Azure Firewall Policy
resource "azurerm_firewall_policy" "fw_policy" {
  name                = "ims-prd-conn-ne-afwp-01"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku             = "Premium"

  threat_intelligence_mode = "Alert"

  # IDPS configuration
  intrusion_detection {
    mode = "Alert"
  }

  # TLS inspection (Explicitly Disabled)
  # tls_inspection {
  #  enabled = false
  # }
}

# 2. Create Azure Firewall
resource "azurerm_firewall" "fw" {
  name                = "ims-prd-conn-ne-afw-01"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Premium"
  firewall_policy_id  = azurerm_firewall_policy.fw_policy.id
  zones               = ["1"]

  ip_configuration {
    name                 = "firewallipconfig"
    subnet_id            = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01/subnets/AzureFirewallSubnet"
    public_ip_address_id = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/publicIPAddresses/ims-prd-conn-ne-pip-afw-01"
  }
}

output "firewall_id" {
  value = azurerm_firewall.fw.id
  description = "Azure Firewall ID"
}
output "firewall_policy_id" {
  value = azurerm_firewall_policy.fw_policy.id
  description = "Firewall Policy ID"
}

# Firewall Rule Collection
resource "azurerm_firewall_policy_rule_collection_group" "coreplat_group" {
  name                = "ims-prd-conn-ne-afwprcg-coreplat"
  firewall_policy_id  = azurerm_firewall_policy.fw_policy.id
  # resource_group_name = var.resource_group_name
  # location            = var.location
  priority           = 100

  # nat_rule_collection {
  #   name     = "ims-prd-conn-ne-afwprc-coreplat-dnat"
  #  priority = 100
  #  action   = "Allow"

  #}
  network_rule_collection {
    name     = "ims-prd-conn-ne-afwprc-coreplat-net"
    priority = 120
    action   = "Allow"

    rule {
      name                  = "ims-prd-conn-ne-afwpr-awsdns-out"
      source_addresses      = ["192.168.0.192/26"]
      destination_addresses = ["10.0.0.0/8"]
      protocols             = ["TCP", "UDP"]
      destination_ports     = ["53"]
      description           = "Enables Azure DNS Private Resolver to forward DNS queries to IMS AWS for conditional forwarding. We should restrict the 10.0.0.0/8 address to a longer prefix once we know what the IP address(es) of the AWS DNS Servers are."
    }

    rule {
      name                  = "ims-prd-conn-ne-afwpr-dns-in"
      source_addresses      = ["10.0.0.0/8", "192.168.4.0/22", "192.168.8.0/22"]
      destination_addresses = ["192.168.0.132"]
      protocols             = ["TCP", "UDP"]
      destination_ports     = ["53"]
      description           = "Enable DNS queries to Azure DNS Private Resolver"
    }

    rule {
      name                  = "ims-prd-conn-ne-afwpr-ziatcp-out"
      source_addresses      = ["192.168.8.0/22"]
      destination_addresses = ["147.161.224.0/23,170.85.58.0/23,165.225.80.0/22,147.161.166.0/23,136.226.166.0/23,136.226.168.0/23,147.161.140.0/23,147.161.142.0/23,147.161.144.0/23,136.226.190.0/23,147.161.236.0/23,165.225.196.0/23,165.225.198.0/23,170.85.84.0/23,194.9.112.0/23,194.9.106.0/23,194.9.108.0/23,194.9.110.0/23,194.9.114.0/23"]
      protocols             = ["TCP"]
      destination_ports     = ["80", "443", "9400", "9480", "9443"]
      description           = "Probably best creating an IP Group with these zscaler IPs, rather than adding them to this rule individually, as it's easier to manage if the IPs change in future."
    }

    rule {
      name                  = "ims-prd-conn-ne-afwpr-ziaudp-out"
      source_addresses      = ["192.168.8.0/22"]
      destination_addresses = ["147.161.224.0/23,170.85.58.0/23,165.225.80.0/22,147.161.166.0/23,136.226.166.0/23,136.226.168.0/23,147.161.140.0/23,147.161.142.0/23,147.161.144.0/23,136.226.190.0/23,147.161.236.0/23,165.225.196.0/23,165.225.198.0/23,170.85.84.0/23,194.9.112.0/23,194.9.106.0/23,194.9.108.0/23,194.9.110.0/23,194.9.114.0/23"]
      protocols             = ["UDP"]
      destination_ports     = ["80", "443"]
      description           = "Probably best creating an IP Group with these zscaler IPs, rather than adding them to this rule individually, as it's easier to manage if the IPs change in future."
    }
    
 # rule {
 #     name                  = "ims-prd-conn-ne-afwpr-mgmtst-out"
 #     source_addresses      = ["192.168.10.0/24"]
 #     destination_service_tags = ["WindowsVirtualDesktop", "AzureMonitor", "EventHub"]
 #     protocols             = ["TCP"]
 #     destination_ports     = ["443"]
 #     description           = "The AVD session hosts needs to access this list of FQDNs and endpoints for Azure Virtual Desktop. All entries are outbound, it is not required to open inbound ports for AVD"
 #   }

rule {
      name                  = "ims-prd-conn-ne-afwpr-mgmtip-out"
      source_addresses      = ["192.168.10.0/24,192.168.8.0/22"]
      destination_addresses = ["169.254.169.254,168.63.129.16"]
      protocols             = ["TCP"]
      destination_ports     = ["3390", "3478", "49152", "65535"]
      description           = "The AVD session hosts needs to access this list of FQDNs and endpoints for Azure Virtual Desktop. All entries are outbound, it is not required to open inbound ports for AVD."
    }

rule {
      name                  = "ims-prd-conn-ne-afwpr-mgmtrdpshortpath-out"
      source_addresses      = ["192.168.10.0/24, 192.168.8.0/22"]
      destination_addresses = ["20.202.0.0/16, 51.5.0.0/16"]
      protocols             = ["UDP"]
      destination_ports     = ["80"]
      description           = "Requirements for RDP Shortpath for the session host virtual network."
    }

rule {
      name                  = "ims-prd-conn-ne-afwpr-avdawsdc-out"
      source_addresses      = ["192.168.8.0/22"]
      destination_addresses = ["10.0.71.42, 10.0.71.80, 10.0.71.171"]
      protocols             = ["TCP", "UDP"]
      destination_ports     = ["53", "88" ,"464", "389"]
      description           = "DNS, Kerberos, Kerberos password change, LDAP"
    }

rule {
      name                  = "ims-prd-conn-ne-afwpr-avdawsdcntp-out"
      source_addresses      = ["192.168.8.0/22"]
      destination_addresses = ["10.0.71.42, 10.0.71.80, 10.0.71.171"]
      protocols             = ["UDP"]
      destination_ports     = ["123"]
      description           = "W32Time"
    }

rule {
      name                  = "ims-prd-conn-ne-afwpr-avdawsdc01-out"
      source_addresses      = ["192.168.8.0/22"]
      destination_addresses = ["10.0.71.42, 10.0.71.80, 10.0.71.171"]
      protocols             = ["TCP"]
      destination_ports     = ["135", "445", "636", "3268", "3269", "49152-65535"]
      description           = "RPC Endpoint Mapper, SMB, LDAP SSL, LDAP GC, LDAP GC SSL, RPC for LSA, SAM, NetLogon"
    }

rule {
      name                  = "ims-prd-conn-ne-afwpr-avdawscert-out"
      source_addresses      = ["192.168.8.0/22"]
      destination_addresses = ["10.0.71.48, 10.0.71.122"]
      protocols             = ["TCP"]
      destination_ports     = ["80", "443", "135", "445"]
      description           = "Web Entrollment, OCSP, NDES"
    }
  }
   
 application_rule_collection {
    name     = "ims-prd-conn-ne-afwprc-coreplat-app"
    priority = 130
    action   = "Allow"

   rule {
      name                  = "ims-prd-conn-ne-afwpr-avdfqdn-out"
      source_addresses      = ["192.168.10.0/24, 192.168.8.0/22"]
      destination_fqdns     = ["login.microsoftonline.com","*.wvd.microsoft.com","catalogartifact.azureedge.net","*.prod.warm.ingest.monitor.core.windows.net","gcs.prod.monitoring.core.windows.net","azkms.core.windows.net","mrsglobalsteus2prod.blob.core.windows.net","wvdportalstorageblob.blob.core.windows.net","oneocsp.microsoft.com","www.microsoft.com","aka.ms","login.windows.net","*.events.data.microsoft.com","www.msftconnecttest.com","*.prod.do.dsp.mp.microsoft.com","*.sfx.ms","*.digicert.com","*.azure-dns.com","*.azure-dns.net","*eh.servicebus.windows.net","ctldl.windowsupdate.com","*.service.windows.cloud.microsoft","*.windows.cloud.microsoft","*.windows.static.microsoft"]
      protocols {
        type = "Http"
        port = 80
      }
      protocols {
        type = "Https"
        port = 443
      }
      # protocols             = ["http","https"]
      # destination_ports     = ["80","443","1688"]
      description           = "The AVD session hosts needs to access these FQDNs and endpoints for Azure Virtual Desktop. All entries are outbound, it is not required to open inbound ports for AVD."
    }
    }
}