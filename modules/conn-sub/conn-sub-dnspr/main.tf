#####################################################################
# Create Azure DNS Private Resolver with Inbound & Outbound Endpoints
#####################################################################

# Create Azure DNS Private Resolver
resource "azurerm_private_dns_resolver" "dnspr" {
  name                = "ims-prd-conn-ne-dnspr-01"
  resource_group_name = var.resource_group_name
  location            = var.location
  virtual_network_id  = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01"

  tags = {
    Name          = "ims-prd-conn-ne-dnspr-01"
    Environment   = "prd"
    DateCreated   = "2025-08-01"
  }
}
# Create DNS Private Resolver Inbound Endpoint
resource "azurerm_private_dns_resolver_inbound_endpoint" "inboundep" {
  name                = "ims-prd-conn-ne-in-dnspr"
  private_dns_resolver_id = azurerm_private_dns_resolver.dnspr.id
  # resource_group_name = var.resource_group_name
  location            = var.location
  # subnet_id           = var.dnspinsubnet

  ip_configurations {
    subnet_id                     = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01/subnets/ims-prd-conn-ne-snet-dnsprin"
    private_ip_allocation_method  = "Static"
    private_ip_address            = "192.168.0.132"
  }

  tags = {
    Name          = "ims-prd-conn-ne-in-dnspr"
    Environment   = "prd"
    DateCreated   = "2025-08-01"
  }
}
# Create DNS Private Resolver Outbound Endpoint
resource "azurerm_private_dns_resolver_outbound_endpoint" "outboundep" {
  name                = "ims-prd-conn-ne-out-dnspr"
  private_dns_resolver_id     = azurerm_private_dns_resolver.dnspr.id
  # resource_group_name = var.resource_group_name
  location            = var.location
  subnet_id           = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/virtualNetworks/ims-prd-conn-ne-vnet-hub-01/subnets/ims-prd-conn-ne-snet-dnsprout"

  tags = {
    Name          = "ims-prd-conn-ne-out-dnspr"
    Environment   = "prd"
    DateCreated   = "2025-08-01"
  }
}

# Create Outbound Endpoint Forwarding Ruleset
resource "azurerm_private_dns_resolver_dns_forwarding_ruleset" "dnsfrs" {
  name                = "ims-prd-conn-ne-dnsfrs-01"
  resource_group_name = var.resource_group_name
  location            = var.location
  # private_dns_resolver_id     = azurerm_private_dns_resolver.dnspr.id

  private_dns_resolver_outbound_endpoint_ids = [azurerm_private_dns_resolver_outbound_endpoint.outboundep.id]
  tags = {
    Name          = "ims-prd-conn-ne-dnsfrs-01"
    Environment   = "prd"
    DateCreated   = "2025-08-01"
  }
}

# Create Outbound Endpoint Forwarding Rule 1
resource "azurerm_private_dns_resolver_forwarding_rule" "dnsfr" {
  name                    = "ims-prd-conn-ne-dnsfrs-rule-01"
  dns_forwarding_ruleset_id = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/dnsForwardingRulesets/ims-prd-conn-ne-dnsfrs-01"
  domain_name             = "tescoims.org."
  enabled                 = true
  target_dns_servers {
    ip_address = "1.1.1.1"
    port       = 53
  }
}
# Create Outbound Endpoint Forwarding Rule 2
resource "azurerm_private_dns_resolver_forwarding_rule" "dnsfr2" {
  name                    = "ims-prd-conn-ne-dnsfrs-rule-02"
  dns_forwarding_ruleset_id = "/subscriptions/ecd60543-12a0-4899-9e5f-21ec01592207/resourceGroups/ims-prd-conn-ne-rg-network/providers/Microsoft.Network/dnsForwardingRulesets/ims-prd-conn-ne-dnsfrs-01"
  domain_name             = "aws.tescoimscloud.org."
  enabled                 = true
  target_dns_servers {
    ip_address = "1.1.1.1"
    port       = 53
  }
}

#####################################################################
# Create Private DNS Zones
#####################################################################
resource "azurerm_private_dns_zone" "multi" {
  provider            = azurerm.ims-prd-connectivity
  for_each            = toset(var.private_dns_zones)
  name                = each.value
  resource_group_name = data.azurerm_resource_group.connsub.name
}
