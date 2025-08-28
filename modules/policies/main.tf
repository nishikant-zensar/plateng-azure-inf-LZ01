
# corp-Additional Parameters-Deploy a route table with specific user defined routes
resource "azurerm_policy_definition" "deploy_custom_route_table" {
  name                = "Deploy-Custom-Route-Table"
  display_name        = "Deploy a route table with specific user defined routes"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Deploys a route table with specific user defined routes when one does not exist. The route table deployed by the policy must be manually associated to subnet(s)"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "Network",
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "1.0.0",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:21:20.9813071Z",
    updatedBy  = null,
    updatedOn  = null
  })

  parameters = jsonencode({
    disableBgpPropagation = {
      type        = "Boolean"
      metadata    = {
        description = "Disable BGP Propagation"
        displayName = "DisableBgpPropagation"
      }
      defaultValue = false
    }
    effect = {
      type = "String"
      metadata = {
        description = "Enable or disable the execution of the policy"
        displayName = "Effect"
      }
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ]
      defaultValue = "DeployIfNotExists"
    }
    requiredRoutes = {
      type = "Array"
      metadata = {
        description = "Routes that must exist in compliant route tables deployed by this policy"
        displayName = "requiredRoutes"
      }
    }
    routeTableName = {
      type = "String"
      metadata = {
        description = "Name of the route table automatically deployed by this policy"
        displayName = "routeTableName"
      }
    }
    vnetRegion = {
      type = "String"
      metadata = {
        description = "Only VNets in this region will be evaluated against this policy"
        displayName = "vnetRegion"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          equals = "Microsoft.Network/virtualNetworks"
          field  = "type"
        },
        {
          equals = "[parameters('vnetRegion')]"
          field  = "location"
        }
      ]
    }
    then = {
      details = {
        deployment = {
          properties = {
            mode = "incremental"
            parameters = {
              disableBgpPropagation = {
                value = "[parameters('disableBgpPropagation')]"
              }
              requiredRoutes = {
                value = "[parameters('requiredRoutes')]"
              }
              routeTableName = {
                value = "[parameters('routeTableName')]"
              }
              vnetRegion = {
                value = "[parameters('vnetRegion')]"
              }
            }
            template = {
              "$schema" = "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              parameters = {
                disableBgpPropagation = {
                  type = "bool"
                }
                requiredRoutes = {
                  type = "array"
                }
                routeTableName = {
                  type = "string"
                }
                vnetRegion = {
                  type = "string"
                }
              }
              resources = [
                {
                  apiVersion = "2021-02-01"
                  location   = "[parameters('vnetRegion')]"
                  name       = "[parameters('routeTableName')]"
                  properties = {
                    disableBgpRoutePropagation = "[parameters('disableBgpPropagation')]"
                  }
                  type = "Microsoft.Network/routeTables"
                }
              ]
            }
          }
        }
        existenceCondition = {
          allOf = [
            {
              equals = "[parameters('routeTableName')]"
              field  = "name"
            },
            {
              count = {
                field = "Microsoft.Network/routeTables/routes[*]"
                where = {
                  in = "[parameters('requiredRoutes')]"
                  value = "[concat(current('Microsoft.Network/routeTables/routes[*].addressPrefix'), ';', current('Microsoft.Network/routeTables/routes[*].nextHopType'), if(equals(toLower(current('Microsoft.Network/routeTables/routes[*].nextHopType')),'virtualappliance'), concat(';', current('Microsoft.Network/routeTables/routes[*].nextHopIpAddress')), ''))]"
                }
              }
              equals = "[length(parameters('requiredRoutes'))]"
            }
          ]
        }
        roleDefinitionIds = [
          "/subscriptions/e867a45d-e513-44ac-931e-4741cef80b24/providers/Microsoft.Authorization/roleDefinitions/4d97b98b-1d4f-4787-a291-c67834d212e7"
        ]
        type = "Microsoft.Network/routeTables"
      }
      effect = "[parameters('effect')]"
    }
  })
}

#corp-Additional Parameters-Deploy an Azure DDoS Network Protection
resource "azurerm_policy_definition" "deploy_ddos_network_protection" {
  name                = "Deploy-DDoSProtection"
  display_name        = "Deploy an Azure DDoS Network Protection"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Deploys an Azure DDoS Network Protection"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "Network",
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "1.0.1",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:21:16.4527194Z",
    updatedBy  = null,
    updatedOn  = null
  })

  parameters = jsonencode({
    ddosName = {
      type = "String"
      metadata = {
        description = "DDoSVnet"
        displayName = "ddosName"
      }
    }
    ddosRegion = {
      type = "String"
      metadata = {
        description = "DDoSVnet location"
        displayName = "ddosRegion"
        strongType  = "location"
      }
    }
    effect = {
      type = "String"
      metadata = {
        description = "Enable or disable the execution of the policy"
        displayName = "Effect"
      }
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ]
      defaultValue = "DeployIfNotExists"
    }
    rgName = {
      type = "String"
      metadata = {
        description = "Provide name for resource group."
        displayName = "rgName"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          equals = "Microsoft.Resources/subscriptions"
          field  = "type"
        }
      ]
    }
    then = {
      details = {
        deployment = {
          location = "northeurope"
          properties = {
            mode = "Incremental"
            parameters = {
              ddosname = {
                value = "[parameters('ddosname')]"
              }
              ddosregion = {
                value = "[parameters('ddosRegion')]"
              }
              rgName = {
                value = "[parameters('rgName')]"
              }
            }
            template = {
              "$schema" = "http://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json"
              contentVersion = "1.0.0.0"
              outputs = {}
              parameters = {
                ddosRegion = {
                  type = "String"
                }
                ddosname = {
                  type = "String"
                }
                rgName = {
                  type = "String"
                }
              }
              resources = [
                {
                  apiVersion = "2018-05-01"
                  location   = "[deployment().location]"
                  name       = "[parameters('rgName')]"
                  properties = {}
                  type       = "Microsoft.Resources/resourceGroups"
                },
                {
                  apiVersion = "2018-05-01"
                  dependsOn  = [
                    "[resourceId('Microsoft.Resources/resourceGroups/', parameters('rgName'))]"
                  ]
                  name = "ddosprotection"
                  properties = {
                    mode = "Incremental"
                    template = {
                      "$schema" = "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json"
                      contentVersion = "1.0.0.0"
                      outputs = {}
                      parameters = {}
                      resources = [
                        {
                          apiVersion = "2019-12-01"
                          location   = "[parameters('ddosRegion')]"
                          name       = "[parameters('ddosName')]"
                          properties = {}
                          type       = "Microsoft.Network/ddosProtectionPlans"
                        }
                      ]
                    }
                  }
                  resourceGroup = "[parameters('rgName')]"
                  type          = "Microsoft.Resources/deployments"
                }
              ]
            }
          }
        }
        deploymentScope = "subscription"
        existenceScope  = "resourceGroup"
        name            = "[parameters('ddosName')]"
        resourceGroupName = "[parameters('rgName')]"
        roleDefinitionIds = [
          "/providers/Microsoft.Authorization/roleDefinitions/4d97b98b-1d4f-4787-a291-c67834d212e7"
        ]
        type = "Microsoft.Network/ddosProtectionPlans"
      }
      effect = "[parameters('effect')]"
    }
  })
}

#corp-Additional Parameters-Deploy Azure Firewall Manager policy in the subscription
resource "azurerm_policy_definition" "deploy_firewall_policy" {
  name                = "Deploy-FirewallPolicy"
  display_name        = "Deploy Azure Firewall Manager policy in the subscription"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Deploys Azure Firewall Manager policy in subscription where the policy is assigned."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "Network",
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "1.0.0",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:21:22.8627252Z",
    updatedBy  = null,
    updatedOn  = null
  })

  parameters = jsonencode({
    effect = {
      type = "String"
      metadata = {
        description = "Enable or disable the execution of the policy"
        displayName = "Effect"
      }
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ]
      defaultValue = "DeployIfNotExists"
    }
    fwPolicyRegion = {
      type = "String"
      metadata = {
        description = "Select Azure region for Azure Firewall Policy"
        displayName = "fwPolicyRegion"
        strongType  = "location"
      }
    }
    fwpolicy = {
      type = "Object"
      metadata = {
        description = "Object describing Azure Firewall Policy"
        displayName = "fwpolicy"
      }
      defaultValue = {}
    }
    rgName = {
      type = "String"
      metadata = {
        description = "Provide name for resource group."
        displayName = "rgName"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          equals = "Microsoft.Resources/subscriptions"
          field  = "type"
        }
      ]
    }
    then = {
      details = {
        deployment = {
          location = "northeurope"
          properties = {
            mode = "Incremental"
            parameters = {
              fwPolicy = {
                value = "[parameters('fwPolicy')]"
              }
              fwPolicyRegion = {
                value = "[parameters('fwPolicyRegion')]"
              }
              rgName = {
                value = "[parameters('rgName')]"
              }
            }
            template = {
              "$schema" = "http://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json"
              contentVersion = "1.0.0.0"
              outputs = {}
              parameters = {
                fwPolicy = {
                  type = "object"
                }
                fwPolicyRegion = {
                  type = "String"
                }
                rgName = {
                  type = "String"
                }
              }
              resources = [
                {
                  apiVersion = "2018-05-01"
                  location   = "[deployment().location]"
                  name       = "[parameters('rgName')]"
                  properties = {}
                  type       = "Microsoft.Resources/resourceGroups"
                },
                {
                  apiVersion = "2018-05-01"
                  dependsOn  = [
                    "[resourceId('Microsoft.Resources/resourceGroups/', parameters('rgName'))]"
                  ]
                  name = "fwpolicies"
                  properties = {
                    mode = "Incremental"
                    template = {
                      "$schema" = "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json"
                      contentVersion = "1.0.0.0"
                      outputs = {}
                      parameters = {}
                      resources = [
                        {
                          apiVersion = "2019-09-01"
                          dependsOn = []
                          location   = "[parameters('fwpolicy').location]"
                          name       = "[parameters('fwpolicy').firewallPolicyName]"
                          properties = {}
                          resources = [
                            {
                              apiVersion = "2019-09-01"
                              dependsOn = [
                                "[resourceId('Microsoft.Network/firewallPolicies',parameters('fwpolicy').firewallPolicyName)]"
                              ]
                              name = "[parameters('fwpolicy').ruleGroups.name]"
                              properties = {
                                priority = "[parameters('fwpolicy').ruleGroups.properties.priority]"
                                rules    = "[parameters('fwpolicy').ruleGroups.properties.rules]"
                              }
                              type = "ruleGroups"
                            }
                          ]
                          tags = {}
                          type = "Microsoft.Network/firewallPolicies"
                        }
                      ]
                      variables = {}
                    }
                  }
                  resourceGroup = "[parameters('rgName')]"
                  type          = "Microsoft.Resources/deployments"
                }
              ]
            }
          }
        }
        deploymentScope = "subscription"
        existenceScope  = "resourceGroup"
        resourceGroupName = "[parameters('rgName')]"
        roleDefinitionIds = [
          "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
        ]
        type = "Microsoft.Network/firewallPolicies"
      }
      effect = "[parameters('effect')]"
    }
  })
}

#corp-Additional Parameters-Deploy Microsoft Defender for Cloud Security Contacts
resource "azurerm_policy_definition" "deploy_asc_security_contacts" {
  name                = "Deploy-ASC-SecurityContacts"
  display_name        = "Deploy Microsoft Defender for Cloud Security Contacts"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Deploy Microsoft Defender for Cloud Security Contacts"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "Security Center",
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "2.0.0",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:21:09.1770467Z",
    updatedBy  = null,
    updatedOn  = null
  })

  parameters = jsonencode({
    effect = {
      type = "String"
      metadata = {
        description = "Enable or disable the execution of the policy"
        displayName = "Effect"
      }
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ]
      defaultValue = "DeployIfNotExists"
    }
    emailSecurityContact = {
      type = "String"
      metadata = {
        description = "Provide email addresses (semi-colon separated) for Defender for Cloud contact details"
        displayName = "Security contacts email address"
      }
    }
    minimalSeverity = {
      type = "String"
      metadata = {
        description = "Defines the minimal alert severity which will be sent as email notifications"
        displayName = "Minimal severity"
      }
      allowedValues = [
        "High",
        "Medium",
        "Low"
      ]
      defaultValue = "High"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          equals = "Microsoft.Resources/subscriptions"
          field  = "type"
        }
      ]
    }
    then = {
      details = {
        deployment = {
          location = "northeurope"
          properties = {
            mode = "incremental"
            parameters = {
              emailSecurityContact = {
                value = "[parameters('emailSecurityContact')]"
              }
              minimalSeverity = {
                value = "[parameters('minimalSeverity')]"
              }
            }
            template = {
              "$schema" = "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              outputs = {}
              parameters = {
                emailSecurityContact = {
                  type = "string"
                  metadata = {
                    description = "Security contacts email address"
                  }
                }
                minimalSeverity = {
                  type = "string"
                  metadata = {
                    description = "Minimal severity level reported"
                  }
                }
              }
              resources = [
                {
                  apiVersion = "2023-12-01-preview"
                  name       = "default"
                  type       = "Microsoft.Security/securityContacts"
                  properties = {
                    emails = "[parameters('emailSecurityContact')]"
                    isEnabled = true
                    notificationsByRole = {
                      roles = [
                        "Owner"
                      ]
                      state = "On"
                    }
                    notificationsSources = [
                      {
                        minimalSeverity = "[parameters('minimalSeverity')]"
                        sourceType = "Alert"
                      }
                    ]
                  }
                }
              ]
              variables = {}
            }
          }
        }
        deploymentScope = "subscription"
        existenceCondition = {
          allOf = [
            {
              contains = "[parameters('emailSecurityContact')]"
              field    = "Microsoft.Security/securityContacts/email"
            },
            {
              equals = true
              field  = "Microsoft.Security/securityContacts/isEnabled"
            },
            {
              contains = "[parameters('minimalSeverity')]"
              field    = "Microsoft.Security/securityContacts/notificationsSources[*].Alert.minimalSeverity"
            }
          ]
        }
        existenceScope = "subscription"
        roleDefinitionIds = [
          "/providers/Microsoft.Authorization/roleDefinitions/fb1c8493-542b-48eb-b624-b4c8fea62acd"
        ]
        type = "Microsoft.Security/securityContacts"
      }
      effect = "[parameters('effect')]"
    }
  })
}

# corp-Additional Parameters-Deploy Private DNS Generic
resource "azurerm_policy_definition" "private_dns_generic" {
  name         = "Deploy-Private-DNS-Generic"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deploy-Private-DNS-Generic"
  description  = "Configure private DNS zone group to override the DNS resolution for PaaS services private endpoint. See https://aka.ms/pepdnszones for information on values to provide to parameters in this policy."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]
  
metadata     = jsonencode({
    category = "Networking"
    version  = "2.0.0"
  })

  parameters = jsonencode({
    effect = {
      type = "String"
      metadata = {
        description = "Enable or disable the execution of the policy"
        displayName = "Effect"
      }
      allowedValues = ["DeployIfNotExists", "Disabled"]
      defaultValue  = "DeployIfNotExists"
    }
    evaluationDelay = {
      type = "String"
      metadata = {
        description = "The delay in evaluation of the policy. Review delay options at https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-deploy-if-not-exists"
        displayName = "Evaluation Delay"
      }
      defaultValue = "PT10M"
    }
    groupId = {
      type = "String"
      metadata = {
        description = "The group ID of the PaaS private endpoint. Also referred to as subresource."
        displayName = "PaaS Private endpoint group ID (subresource)"
      }
    }
    location = {
      type = "String"
      metadata = {
        description = "Specify the Private Endpoint location"
        displayName = "Location (Specify the Private Endpoint location)"
        strongType  = "location"
      }
      defaultValue = "northeurope"
    }
    privateDnsZoneId = {
      type = "String"
      metadata = {
        assignPermissions = true
        description       = "The private DNS zone name required for specific PaaS Services to resolve a private DNS Zone."
        displayName       = "Private DNS Zone ID for PaaS services"
        strongType        = "Microsoft.Network/privateDnsZones"
      }
    }
    resourceType = {
      type = "String"
      metadata = {
        description = "The PaaS endpoint resource type."
        displayName = "PaaS private endpoint resource type"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          equals = "[parameters('location')]"
          field  = "location"
        },
        {
          equals = "Microsoft.Network/privateEndpoints"
          field  = "type"
        },
        {
          count = {
            field = "Microsoft.Network/privateEndpoints/privateLinkServiceConnections[*]"
            where = {
              allOf = [
                {
                  contains = "[parameters('resourceType')]"
                  field    = "Microsoft.Network/privateEndpoints/privateLinkServiceConnections[*].privateLinkServiceId"
                },
                {
                  equals = "[parameters('groupId')]"
                  field  = "Microsoft.Network/privateEndpoints/privateLinkServiceConnections[*].groupIds[*]"
                }
              ]
            }
          }
          greaterOrEquals = 1
        }
      ]
    }
    then = {
      details = {
        deployment = {
          properties = {
            mode = "incremental"
            parameters = {
              location = {
                value = "[field('location')]"
              }
              privateDnsZoneId = {
                value = "[parameters('privateDnsZoneId')]"
              }
              privateEndpointName = {
                value = "[field('name')]"
              }
            }
            template = {
              "$schema" = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              parameters = {
                location = {
                  type = "string"
                }
                privateDnsZoneId = {
                  type = "string"
                }
                privateEndpointName = {
                  type = "string"
                }
              }
              resources = [
                {
                  apiVersion = "2020-03-01"
                  location   = "[parameters('location')]"
                  name       = "[concat(parameters('privateEndpointName'), '/deployedByPolicy')]"
                  properties = {
                    privateDnsZoneConfigs = [
                      {
                        name = "PaaS-Service-Private-DNS-Zone-Config"
                        properties = {
                          privateDnsZoneId = "[parameters('privateDnsZoneId')]"
                        }
                      }
                    ]
                  }
                  type = "Microsoft.Network/privateEndpoints/privateDnsZoneGroups"
                }
              ]
            }
          }
        }
        evaluationDelay = "[parameters('evaluationDelay')]"
        roleDefinitionIds = [
          "/providers/Microsoft.Authorization/roleDefinitions/4d97b98b-1d4f-4787-a291-c67834d212e7"
        ]
        type = "Microsoft.Network/privateEndpoints/privateDnsZoneGroups"
      }
      effect = "[parameters('effect')]"
    }
  })
}

#corp-Additional Parameters-Deploy SQL database auditing settings
resource "azurerm_policy_definition" "deploy_sql_vulnerability_assessments" {
  name                = "Deploy-Sql-vulnerabilityAssessments"
  display_name        = "Deploy SQL Database Vulnerability Assessments"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Deploy SQL Database Vulnerability Assessments when it does not exist in the deployment, and save results to the storage account specified in the parameters."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "SQL",
    version  = "1.0.0",
    source   = "https://github.com/Azure/Enterprise-Scale/"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy"
        displayName = "Effect"
      },
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ],
      defaultValue = "DeployIfNotExists"
    },
    vulnerabilityAssessmentsEmail = {
      type = "Array",
      metadata = {
        description = "The email address(es) to send alerts."
        displayName = "The email address(es) to send alerts."
      }
    },
    vulnerabilityAssessmentsStorageID = {
      type = "String",
      metadata = {
        assignPermissions = true,
        description = "The storage account ID to store assessments",
        displayName = "The storage account ID to store assessments"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      field  = "type",
      equals = "Microsoft.Sql/servers/databases"
    },
    then = {
      details = {
        deployment = {
          properties = {
            mode = "Incremental",
            parameters = {
              location = {
                value = "[field('location')]"
              },
              sqlServerDataBaseName = {
                value = "[field('name')]"
              },
              sqlServerName = {
                value = "[first(split(field('fullname'),'/'))]"
              },
              vulnerabilityAssessmentsEmail = {
                value = "[parameters('vulnerabilityAssessmentsEmail')]"
              },
              vulnerabilityAssessmentsStorageID = {
                value = "[parameters('vulnerabilityAssessmentsStorageID')]"
              }
            },
            template = {
              "$schema" = "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
              contentVersion = "1.0.0.0",
              outputs = {},
              parameters = {
                location = {
                  type = "String"
                },
                sqlServerDataBaseName = {
                  type = "String"
                },
                sqlServerName = {
                  type = "String"
                },
                vulnerabilityAssessmentsEmail = {
                  type = "Array"
                },
                vulnerabilityAssessmentsStorageID = {
                  type = "String"
                }
              },
              resources = [
                {
                  apiVersion = "2017-03-01-preview",
                  name = "[concat(parameters('sqlServerName'),'/',parameters('sqlServerDataBaseName'),'/default')]",
                  type = "Microsoft.Sql/servers/databases/vulnerabilityAssessments",
                  properties = {
                    recurringScans = {
                      emailSubscriptionAdmins = false,
                      emails = "[parameters('vulnerabilityAssessmentsEmail')]",
                      isEnabled = true
                    },
                    storageAccountAccessKey = "[listKeys(parameters('vulnerabilityAssessmentsStorageID'), '2019-06-01').keys[0].value]",
                    storageContainerPath = "[concat('https://', last(split(parameters('vulnerabilityAssessmentsStorageID'), '/')), '.blob.core.windows.net/vulnerabilitylogs')]"
                  }
                }
              ],
              variables = {}
            }
          }
        },
        existenceCondition = {
          allOf = [
            {
              equals = true,
              field  = "Microsoft.Sql/servers/databases/vulnerabilityAssessments/recurringScans.isEnabled"
            }
          ]
        },
        roleDefinitionIds = [
          "/providers/Microsoft.Authorization/roleDefinitions/056cd41c-7e88-42e1-933e-88ba6a50c9c3",
          "/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa",
          "/providers/Microsoft.Authorization/roleDefinitions/17d1049b-9a84-46fb-8f53-869881c3d3ab"
        ],
              type = "Microsoft.Sql/servers/databases/vulnerabilityAssessments"
            },
            effect = "[parameters('effect')]"
          }
        })
      }
#corp-Additional Parameters-Deploy Virtual Network with peering to the hub
resource "azurerm_policy_definition" "deploy_vnet_hubspoke" {
  name                = "Deploy-VNET-HubSpoke"
  display_name        = "Deploy Virtual Network with peering to the hub"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy deploys virtual network and peer to the hub"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "Network",
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "1.1.0",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:21:21.4492159Z",
    updatedBy  = null,
    updatedOn  = null
  })

  parameters = jsonencode({
    dnsServers = {
      type = "Array",
      metadata = {
        description = "Default domain servers for the vNET.",
        displayName = "DNSServers"
      },
      defaultValue = []
    },
    hubResourceId = {
      type = "String",
      metadata = {
        description = "Resource ID for the HUB vNet",
        displayName = "hubResourceId"
      }
    },
    vNetCidrRange = {
      type = "String",
      metadata = {
        description = "CIDR Range for the vNet",
        displayName = "vNetCidrRange"
      }
    },
    vNetLocation = {
      type = "String",
      metadata = {
        description = "Location for the vNet",
        displayName = "vNetLocation"
      }
    },
    vNetName = {
      type = "String",
      metadata = {
        description = "Name of the landing zone vNet",
        displayName = "vNetName"
      }
    },
    vNetPeerUseRemoteGateway = {
      type = "Boolean",
      metadata = {
        description = "Enable gateway transit for the LZ network",
        displayName = "vNetPeerUseRemoteGateway"
      },
      defaultValue = false
    },
    vNetRgName = {
      type = "String",
      metadata = {
        description = "Name of the landing zone vNet RG",
        displayName = "vNetRgName"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          equals = "Microsoft.Resources/subscriptions",
          field  = "type"
        }
      ]
    },
    then = {
      details = {
        ResourceGroupName = "[parameters('vNetRgName')]",
        deployment = {
          location = "northeurope",
          properties = {
            mode = "Incremental",
            parameters = {
              dnsServers = {
                value = "[parameters('dnsServers')]"
              },
              hubResourceId = {
                value = "[parameters('hubResourceId')]"
              },
              vNetCidrRange = {
                value = "[parameters('vNetCidrRange')]"
              },
              vNetLocation = {
                value = "[parameters('vNetLocation')]"
              },
              vNetName = {
                value = "[parameters('vNetName')]"
              },
              vNetPeerUseRemoteGateway = {
                value = "[parameters('vNetPeerUseRemoteGateway')]"
              },
              vNetRgName = {
                value = "[parameters('vNetRgName')]"
              }
            },
            template = {
              "$schema" = "http://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json",
              contentVersion = "1.0.0.0",
              outputs = {},
              parameters = {
                dnsServers = {
                  defaultValue = [],
                  type = "Array"
                },
                hubResourceId = {
                  type = "String"
                },
                vNetCidrRange = {
                  type = "String"
                },
                vNetLocation = {
                  type = "String"
                },
                vNetName = {
                  type = "String"
                },
                vNetPeerUseRemoteGateway = {
                  defaultValue = false,
                  type = "bool"
                },
                vNetRgName = {
                  type = "String"
                }
              },
              resources = [
                {
                  apiVersion = "2021-02-01",
                  location = "[parameters('vNetLocation')]",
                  name = "[parameters('vNetName')]",
                  properties = {
                    addressSpace = {
                      addressPrefixes = [
                        "[parameters('vNetCidrRange')]"
                      ]
                    },
                    dhcpOptions = {
                      dnsServers = "[parameters('dnsServers')]"
                    }
                  },
                  type = "Microsoft.Network/virtualNetworks"
                },
                {
                  apiVersion = "2021-02-01",
                  name = "[concat(parameters('vNetName'), '/peerToHub')]",
                  properties = {
                    allowForwardedTraffic = true,
                    allowGatewayTransit = false,
                    allowVirtualNetworkAccess = true,
                    remoteVirtualNetwork = {
                      id = "[parameters('hubResourceId')]"
                    },
                    useRemoteGateways = "[parameters('vNetPeerUseRemoteGateway')]"
                  },
                  type = "Microsoft.Network/virtualNetworks/virtualNetworkPeerings"
                }
              ],
              variables = {}
            }
          }
        },
        deploymentScope = "resourceGroup",
        existenceCondition = {
          allOf = [
            {
              field = "name",
              like = "[parameters('vNetName')]"
            },
            {
              equals = "[parameters('vNetLocation')]",
              field = "location"
            }
          ]
        },
        existenceScope = "resourceGroup",
        name = "[parameters('vNetName')]",
        roleDefinitionIds = [
          "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
        ],
        type = "Microsoft.Network/virtualNetworks"
      },
      effect = "DeployIfNotExists"
    }
  })
}

#corp-Additional Parameters-Deploy Windows Domain Join Extension with keyvault configuration
resource "azurerm_policy_definition" "deploy_windows_domainjoin_extension_with_keyvault" {
  name                = "Deploy-Windows-DomainJoin"
  display_name        = "Deploy Windows Domain Join Extension with keyvault configuration"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Deploy Windows Domain Join Extension with keyvault configuration when the extension does not exist on a given Windows Virtual Machine"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category = "Guest Configuration",
    source   = "https://github.com/Azure/Enterprise-Scale/",
    version  = "1.0.0"
  })

  parameters = jsonencode({
    domainFQDN = {
      type = "String",
      metadata = {
        displayName = "domainFQDN"
      }
    },
    domainOUPath = {
      type = "String",
      metadata = {
        displayName = "domainOUPath"
      }
    },
    domainPassword = {
      type = "String",
      metadata = {
        displayName = "domainPassword"
      }
    },
    domainUsername = {
      type = "String",
      metadata = {
        displayName = "domainUsername"
      }
    },
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy",
        displayName = "Effect"
      },
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ],
      defaultValue = "DeployIfNotExists"
    },
    keyVaultResourceId = {
      type = "String",
      metadata = {
        displayName = "keyVaultResourceId"
      }
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "equals" = "Microsoft.Compute/virtualMachines",
          "field"  = "type"
        },
        {
          "equals" = "MicrosoftWindowsServer",
          "field"  = "Microsoft.Compute/imagePublisher"
        },
        {
          "equals" = "WindowsServer",
          "field"  = "Microsoft.Compute/imageOffer"
        },
        {
          "field" = "Microsoft.Compute/imageSKU",
          "in" = [
            "2008-R2-SP1",
            "2008-R2-SP1-smalldisk",
            "2008-R2-SP1-zhcn",
            "2012-Datacenter",
            "2012-datacenter-gensecond",
            "2012-Datacenter-smalldisk",
            "2012-datacenter-smalldisk-g2",
            "2012-Datacenter-zhcn",
            "2012-datacenter-zhcn-g2",
            "2012-R2-Datacenter",
            "2012-r2-datacenter-gensecond",
            "2012-R2-Datacenter-smalldisk",
            "2012-r2-datacenter-smalldisk-g2",
            "2012-R2-Datacenter-zhcn",
            "2012-r2-datacenter-zhcn-g2",
            "2016-Datacenter",
            "2016-datacenter-gensecond",
            "2016-datacenter-gs",
            "2016-Datacenter-Server-Core",
            "2016-datacenter-server-core-g2",
            "2016-Datacenter-Server-Core-smalldisk",
            "2016-datacenter-server-core-smalldisk-g2",
            "2016-Datacenter-smalldisk",
            "2016-datacenter-smalldisk-g2",
            "2016-Datacenter-with-Containers",
            "2016-datacenter-with-containers-g2",
            "2016-Datacenter-with-RDSH",
            "2016-Datacenter-zhcn",
            "2016-datacenter-zhcn-g2",
            "2019-Datacenter",
            "2019-Datacenter-Core",
            "2019-datacenter-core-g2",
            "2019-Datacenter-Core-smalldisk",
            "2019-datacenter-core-smalldisk-g2",
            "2019-Datacenter-Core-with-Containers",
            "2019-datacenter-core-with-containers-g2",
            "2019-Datacenter-Core-with-Containers-smalldisk",
            "2019-datacenter-core-with-containers-smalldisk-g2",
            "2019-datacenter-gensecond",
            "2019-datacenter-gs",
            "2019-Datacenter-smalldisk",
            "2019-datacenter-smalldisk-g2",
            "2019-Datacenter-with-Containers",
            "2019-datacenter-with-containers-g2",
            "2019-Datacenter-with-Containers-smalldisk",
            "2019-datacenter-with-containers-smalldisk-g2",
            "2019-Datacenter-zhcn",
            "2019-datacenter-zhcn-g2",
            "Datacenter-Core-1803-with-Containers-smalldisk",
            "datacenter-core-1803-with-containers-smalldisk-g2",
            "Datacenter-Core-1809-with-Containers-smalldisk",
            "datacenter-core-1809-with-containers-smalldisk-g2",
            "Datacenter-Core-1903-with-Containers-smalldisk",
            "datacenter-core-1903-with-containers-smalldisk-g2",
            "datacenter-core-1909-with-containers-smalldisk",
            "datacenter-core-1909-with-containers-smalldisk-g1",
            "datacenter-core-1909-with-containers-smalldisk-g2"
          ]
        }
      ]
    },
    "then" = {
      "details" = {
        "deployment" = {
          "properties" = {
            "mode" = "Incremental",
            "parameters" = {
              "domainFQDN" = {
                "value" = "[parameters('domainFQDN')]"
              },
              "domainOUPath" = {
                "value" = "[parameters('domainOUPath')]"
              },
              "domainPassword" = {
                "reference" = {
                  "keyVault" = {
                    "id" = "[parameters('keyVaultResourceId')]"
                  },
                  "secretName" = "[parameters('domainPassword')]"
                }
              },
              "domainUsername" = {
                "reference" = {
                  "keyVault" = {
                    "id" = "[parameters('keyVaultResourceId')]"
                  },
                  "secretName" = "[parameters('domainUsername')]"
                }
              },
              "keyVaultResourceId" = {
                "value" = "[parameters('keyVaultResourceId')]"
              },
              "location" = {
                "value" = "[field('location')]"
              },
              "vmName" = {
                "value" = "[field('name')]"
              }
            },
            "template" = {
              "$schema" = "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
              "contentVersion" = "1.0.0.0",
              "outputs" = {},
              "parameters" = {
                "domainFQDN" = {
                  "type" = "String"
                },
                "domainOUPath" = {
                  "type" = "String"
                },
                "domainPassword" = {
                  "type" = "securestring"
                },
                "domainUsername" = {
                  "type" = "String"
                },
                "keyVaultResourceId" = {
                  "type" = "String"
                },
                "location" = {
                  "type" = "String"
                },
                "vmName" = {
                  "type" = "String"
                }
              },
              "resources" = [
                {
                  "apiVersion" = "2015-06-15",
                  "location"   = "[resourceGroup().location]",
                  "name"       = "[concat(variables('vmName'),'/joindomain')]",
                  "properties" = {
                    "autoUpgradeMinorVersion" = true,
                    "protectedSettings" = {
                      "Password" = "[parameters('domainPassword')]"
                    },
                    "publisher" = "Microsoft.Compute",
                    "settings" = {
                      "Name"    = "[parameters('domainFQDN')]",
                      "OUPath"  = "[parameters('domainOUPath')]",
                      "Options" = "[variables('domainJoinOptions')]",
                      "Restart" = "true",
                      "User"    = "[parameters('domainUsername')]"
                    },
                    "type" = "JsonADDomainExtension",
                    "typeHandlerVersion" = "1.3"
                  },
                  "type" = "Microsoft.Compute/virtualMachines/extensions"
                }
              ],
              "variables" = {
                "domainJoinOptions" = 3,
                "vmName" = "[parameters('vmName')]"
              }
            }
          }
        },
        "existenceCondition" = {
          "allOf" = [
            {
              "equals" = "JsonADDomainExtension",
              "field"  = "Microsoft.Compute/virtualMachines/extensions/type"
            },
            {
              "equals" = "Microsoft.Compute",
              "field"  = "Microsoft.Compute/virtualMachines/extensions/publisher"
            }
          ]
        },
        "roleDefinitionIds" = [
          "/providers/Microsoft.Authorization/roleDefinitions/9980e02c-c2be-4d73-94e8-173b1dc7cf3c"
        ],
        "type" = "Microsoft.Compute/virtualMachines/extensions"
      },
      "effect" = "[parameters('effect')]"
    }
  })
}
#corp-Additional Parameters-Enforce specific configuration of User Defined Routes (UDR)
resource "azurerm_policy_definition" "modify_udr" {
  name                = "Modify-UDR"
  display_name        = "Enforce specific configuration of User-Defined Routes (UDR)"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy enforces the configuration of User-Defined Routes (UDR) within a subnet."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "Network",
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "1.0.0",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:21:24.0971427Z",
    updatedBy  = null,
    updatedOn  = null
  })

  parameters = jsonencode({
    addressPrefix = {
      type = "String",
      metadata = {
        description = "The destination IP address range in CIDR notation that this Policy checks for within the UDR. Example: 0.0.0.0/0 to check for the presence of a default route.",
        displayName = "Address Prefix"
      }
    },
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy",
        displayName = "Effect"
      },
      allowedValues = [
        "Modify",
        "Disabled"
      ],
      defaultValue = "Modify"
    },
    nextHopIpAddress = {
      type = "String",
      metadata = {
        description = "The IP address packets should be forwarded to.",
        displayName = "Next Hop IP Address"
      }
    },
    nextHopType = {
      type = "String",
      metadata = {
        description = "The next hope type that the policy checks for within the inspected route. The value can be Virtual Network, Virtual Network Gateway, Internet, Virtual Appliance, or None.",
        displayName = "Next Hop Type"
      },
      allowedValues = [
        "VnetLocal",
        "VirtualNetworkGateway",
        "Internet",
        "VirtualAppliance",
        "None"
      ]
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          equals = "Microsoft.Network/routeTables",
          field  = "type"
        },
        {
          count = {
            field = "Microsoft.Network/routeTables/routes[*]"
          },
          equals = 0
        }
      ]
    },
    then = {
      details = {
        conflictEffect = "audit",
        operations = [
          {
            field     = "Microsoft.Network/routeTables/routes[*]",
            operation = "add",
            value = {
              name = "default",
              properties = {
                addressPrefix    = "[parameters('addressPrefix')]",
                nextHopIpAddress = "[parameters('nextHopIpAddress')]",
                nextHopType      = "[parameters('nextHopType')]"
              }
            }
          }
        ],
        roleDefinitionIds = [
          "/providers/microsoft.authorization/roleDefinitions/4d97b98b-1d4f-4787-a291-c67834d212e7"
        ]
      },
      effect = "[parameters('effect')]"
    }
  })
}
#corp-Additional Parameters-Ensure a Custom Role is Assigned Permissions for Administering Resource Locks
resource "azurerm_policy_definition" "custom_role_administer_resource_locks" {
  name                = "Custom-Role-Administer-Resource-Locks"
  display_name        = "Ensure a Custom Role is Assigned Permissions for Administering Resource Locks"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy ensures that a custom role with permissions to administer resource locks is assigned."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Authorization"
  })

  parameters = jsonencode({
    roleDefinitionId = {
      type = "String",
      metadata = {
        description = "The ID of the custom role that should have permissions for resource locks.",
        displayName = "Role Definition ID"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Authorization/roleAssignments"
        },
        {
          field  = "Microsoft.Authorization/roleAssignments/roleDefinitionId",
          equals = "[parameters('roleDefinitionId')]"
        }
      ]
    },
    then = {
      effect = "audit"
    }
  })
}
#corp-Additional Parameters-Ensure Trusted Locations Are Defined
resource "azurerm_policy_definition" "trusted_locations_defined" {
  name                = "Trusted-Locations-Defined"
  display_name        = "Ensure Trusted Locations Are Defined"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy audits resources that are deployed outside of the specified trusted locations."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({
    allowedLocations = {
      type = "Array",
      metadata = {
        description = "The list of allowed locations.",
        displayName = "Allowed Locations"
      }
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "location",
          "notIn"  = "[parameters('allowedLocations')]"
        }
      ]
    },
    "then" = {
      "effect" = "audit"
    }
  })
}
#corp-Audit-Subnet-Without-Penp-Audit Subnets without Private Endpoint Network Policies enabled
resource "azurerm_policy_definition" "audit_subnet_without_penp" {
  name                = "Audit-Subnet-Without-Penp"
  display_name        = "Subnets without Private Endpoint Network Policies enabled should be audited"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy audits the subnet without Private Endpoint Network Policies enabled. This policy is intended for 'workload' subnets, not 'central infrastructure' (aka, 'hub') subnets."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category  = "Network",
    source    = "https://github.com/Azure/Enterprise-Scale/",
    version   = "1.0.0"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect determines what happens when the policy rule is evaluated to match",
        displayName = "Effect"
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    },
    excludedSubnets = {
      type = "Array",
      metadata = {
        description = "Array of subnet names that are excluded from this policy",
        displayName = "Excluded Subnets"
      },
      defaultValue = [
        "GatewaySubnet",
        "AzureFirewallSubnet",
        "AzureFirewallManagementSubnet",
        "AzureBastionSubnet"
      ]
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "anyOf" = [
        {
          "allOf" = [
            {
              "equals" = "Microsoft.Network/virtualNetworks",
              "field"  = "type"
            },
            {
              "count" = {
                "field" = "Microsoft.Network/virtualNetworks/subnets[*]",
                "where" = {
                  "allOf" = [
                    {
                      "field"     = "Microsoft.Network/virtualNetworks/subnets[*].privateEndpointNetworkPolicies",
                      "notEquals" = "Enabled"
                    },
                    {
                      "field"     = "Microsoft.Network/virtualNetworks/subnets[*].name",
                      "notIn"     = "[parameters('excludedSubnets')]"
                    }
                  ]
                }
              },
              "notEquals" = 0
            }
          ]
        },
        {
          "allOf" = [
            {
              "equals" = "Microsoft.Network/virtualNetworks/subnets",
              "field"  = "type"
            },
            {
              "field"  = "name",
              "notIn"  = "[parameters('excludedSubnets')]"
            },
            {
              "field"     = "Microsoft.Network/virtualNetworks/subnets/privateEndpointNetworkPolicies",
              "notEquals" = "Enabled"
            }
          ]
        }
      ]
    },
    "then" = {
      "effect" = "[parameters('effect')]"
    }
  })
}

#corp-Azure Database for MySQL server deploy a specific min TLS version and enforce SSL
resource "azurerm_policy_definition" "deploy_mysql_ssl_min_tls" {
  name         = "Deploy-MySQL-sslEnforcement"
  display_name = "Azure Database for MySQL server deploy a specific min TLS version and enforce SSL."
  policy_type  = "Custom"
  mode         = "Indexed"
  description  = "Deploy a specific min TLS version requirement and enforce SSL on Azure Database for MySQL server. Enforce the Server to client applications using minimum version of Tls to secure the connection between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application. This configuration enforces that SSL is always enabled for accessing your database server."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

  
 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]
  
  metadata     = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ]
    category = "SQL"
    source   = "https://github.com/Azure/Enterprise-Scale/"
    version  = "1.2.0"
  })

  parameters = jsonencode({
    effect = {
      type = "String"
      metadata = {
        description = "Enable or disable the execution of the policy minimum TLS version Azure Database for MySQL server"
        displayName = "Effect minimum TLS version Azure Database for MySQL server"
      }
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ]
      defaultValue = "DeployIfNotExists"
    }
    minimalTlsVersion = {
      type = "String"
      metadata = {
        description = "Select version  minimum TLS version Azure Database for MySQL server to enforce"
        displayName = "Select version minimum TLS for MySQL server"
      }
      allowedValues = [
        "TLS1_2",
        "TLS1_0",
        "TLS1_1",
        "TLSEnforcementDisabled"
      ]
      defaultValue = "TLS1_2"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          equals = "Microsoft.DBforMySQL/servers"
          field  = "type"
        },
        {
          anyOf = [
            {
              field     = "Microsoft.DBforMySQL/servers/sslEnforcement"
              notEquals = "Enabled"
            },
            {
              field = "Microsoft.DBforMySQL/servers/minimalTlsVersion"
              less  = "[parameters('minimalTlsVersion')]"
            }
          ]
        }
      ]
    }
    then = {
      effect = "[parameters('effect')]"
      details = {
        deployment = {
          properties = {
            mode = "Incremental"
            parameters = {
              location = {
                value = "[field('location')]"
              }
              minimalTlsVersion = {
                value = "[parameters('minimalTlsVersion')]"
              }
              resourceName = {
                value = "[field('name')]"
              }
            }
            template = {
              "$schema"        = "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"
              contentVersion   = "1.0.0.0"
              outputs          = {}
              parameters = {
                location = {
                  type = "String"
                }
                minimalTlsVersion = {
                  type = "String"
                }
                resourceName = {
                  type = "String"
                }
              }
              resources = [
                {
                  apiVersion = "2017-12-01"
                  location   = "[parameters('location')]"
                  name       = "[concat(parameters('resourceName'))]"
                  properties = {
                    minimalTlsVersion = "[parameters('minimalTlsVersion')]"
                    sslEnforcement    = "[if(equals(parameters('minimalTlsVersion'), 'TLSEnforcementDisabled'),'Disabled', 'Enabled')]"
                  }
                  type = "Microsoft.DBforMySQL/servers"
                }
              ]
              variables = {}
            }
          }
        }
        existenceCondition = {
          allOf = [
            {
              equals = "Enabled"
              field  = "Microsoft.DBforMySQL/servers/sslEnforcement"
            },
            {
              equals = "[parameters('minimalTlsVersion')]"
              field  = "Microsoft.DBforMySQL/servers/minimalTlsVersion"
            }
          ]
        }
        roleDefinitionIds = [
          "/providers/microsoft.authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
        ]
        type = "Microsoft.DBforMySQL/servers"
      }
    }
  })
}
#corp-Azure DB for PostgreSQL server deploy a specific min TLS version re
resource "azurerm_policy_definition" "postgresql_min_tls_and_ssl" {
  name                = "Deploy-PostgreSQL-sslEnforcement"
  display_name        = "Azure Database for PostgreSQL server deploy a specific min TLS version requirement and enforce SSL"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Deploy a specific min TLS version requirement and enforce SSL on Azure Database for PostgreSQL server. Enforces that SSL is always enabled and a minimum TLS version is set to help protect against 'man in the middle' attacks."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category = "SQL",
    source   = "https://github.com/Azure/Enterprise-Scale/",
    version  = "1.2.0"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy minimum TLS version Azure Database for PostgreSQL server",
        displayName = "Effect Azure Database for PostgreSQL server"
      },
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ],
      defaultValue = "DeployIfNotExists"
    },
    minimalTlsVersion = {
      type = "String",
      metadata = {
        description = "Select version minimum TLS version Azure Database for PostgreSQL server to enforce",
        displayName = "Select version for PostgreSQL server"
      },
      allowedValues = [
        "TLS1_2",
        "TLS1_0",
        "TLS1_1",
        "TLSEnforcementDisabled"
      ],
      defaultValue = "TLS1_2"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "equals" = "Microsoft.DBforPostgreSQL/servers",
          "field"  = "type"
        },
        {
          "anyOf" = [
            {
              "field"     = "Microsoft.DBforPostgreSQL/servers/sslEnforcement",
              "notEquals" = "Enabled"
            },
            {
              "field" = "Microsoft.DBforPostgreSQL/servers/minimalTlsVersion",
              "less"  = "[parameters('minimalTlsVersion')]"
            }
          ]
        }
      ]
    },
    "then" = {
      "details" = {
        "deployment" = {
          "properties" = {
            "mode" = "Incremental",
            "parameters" = {
              "location" = {
                "value" = "[field('location')]"
              },
              "minimalTlsVersion" = {
                "value" = "[parameters('minimalTlsVersion')]"
              },
              "resourceName" = {
                "value" = "[field('name')]"
              }
            },
            "template" = {
              "$schema" = "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
              "contentVersion" = "1.0.0.0",
              "outputs" = {},
              "parameters" = {
                "location" = {
                  "type" = "String"
                },
                "minimalTlsVersion" = {
                  "type" = "String"
                },
                "resourceName" = {
                  "type" = "String"
                }
              },
              "resources" = [
                {
                  "apiVersion" = "2017-12-01",
                  "location"   = "[parameters('location')]",
                  "name"       = "[concat(parameters('resourceName'))]",
                  "properties" = {
                    "minimalTlsVersion" = "[parameters('minimalTlsVersion')]",
                    "sslEnforcement"    = "[if(equals(parameters('minimalTlsVersion'), 'TLSEnforcementDisabled'),'Disabled', 'Enabled')]"
                  },
                  "type" = "Microsoft.DBforPostgreSQL/servers"
                }
              ],
              "variables" = {}
            }
          }
        },
        "existenceCondition" = {
          "allOf" = [
            {
              "equals" = "Enabled",
              "field"  = "Microsoft.DBforPostgreSQL/servers/sslEnforcement"
            },
            {
              "equals" = "[parameters('minimalTlsVersion')]",
              "field"  = "Microsoft.DBforPostgreSQL/servers/minimalTlsVersion"
            }
          ]
        },
        "roleDefinitionIds" = [
          "/providers/microsoft.authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
        ],
        "type" = "Microsoft.DBforPostgreSQL/servers"
      },
      "effect" = "[parameters('effect')]"
    }
  })
}
#corp-Azure Storage deploy a specific min TLS version requirement and enforce SSLHTTPS
resource "azurerm_policy_definition" "deploy_storage_ssl_enforcement" {
  name                = "Deploy-Storage-sslEnforcement"
  display_name        = "Azure Storage deploy a specific min TLS version requirement and enforce SSL/HTTPS"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Deploy a specific min TLS version requirement and enforce SSL on Azure Storage. Enables secure server to client by enforce minimal Tls Version to secure the connection between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application. This configuration enforces that SSL is always enabled for accessing your Azure Storage."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "Storage",
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "1.3.0",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:21:06.7604768Z",
    updatedBy  = null,
    updatedOn  = null
  })

  parameters = jsonencode({
    effect = {
      type = "String"
      metadata = {
        description = "Enable or disable the execution of the policy minimum TLS version Azure STorage"
        displayName = "Effect Azure Storage"
      }
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ]
      defaultValue = "DeployIfNotExists"
    }
    minimumTlsVersion = {
      type = "String"
      metadata = {
        description = "Select version minimum TLS version Azure STorage to enforce"
        displayName = "Select TLS version for Azure Storage server"
      }
      allowedValues = [
        "TLS1_2",
        "TLS1_1",
        "TLS1_0"
      ]
      defaultValue = "TLS1_2"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          equals = "Microsoft.Storage/storageAccounts"
          field  = "type"
        },
        {
          anyOf = [
            {
              field     = "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly"
              notEquals = "true"
            },
            {
              field = "Microsoft.Storage/storageAccounts/minimumTlsVersion"
              less  = "[parameters('minimumTlsVersion')]"
            }
          ]
        }
      ]
    }
    then = {
      details = {
        deployment = {
          properties = {
            mode = "Incremental"
            parameters = {
              location = {
                value = "[field('location')]"
              }
              minimumTlsVersion = {
                value = "[parameters('minimumTlsVersion')]"
              }
              resourceName = {
                value = "[field('name')]"
              }
            }
            template = {
              "$schema"      = "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              outputs        = {}
              parameters = {
                location = {
                  type = "String"
                }
                minimumTlsVersion = {
                  type = "String"
                }
                resourceName = {
                  type = "String"
                }
              }
              resources = [
                {
                  apiVersion = "2019-06-01"
                  location   = "[parameters('location')]"
                  name       = "[concat(parameters('resourceName'))]"
                  properties = {
                    minimumTlsVersion        = "[parameters('minimumTlsVersion')]"
                    supportsHttpsTrafficOnly = true
                  }
                  type = "Microsoft.Storage/storageAccounts"
                }
              ]
              variables = {}
            }
          }
        }
        existenceCondition = {
          allOf = [
            {
              equals = "true"
              field  = "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly"
            },
            {
              equals = "[parameters('minimumTlsVersion')]"
              field  = "Microsoft.Storage/storageAccounts/minimumTlsVersion"
            }
          ]
        }
        name              = "current"
        roleDefinitionIds = [
          "/providers/microsoft.authorization/roleDefinitions/17d1049b-9a84-46fb-8f53-869881c3d3ab"
        ]
        type = "Microsoft.Storage/storageAccounts"
      }
      effect = "[parameters('effect')]"
    }
  })
}
#corp-Configure Logic apps to use the latest TLS version
resource "azurerm_policy_definition" "logic_apps_latest_tls" {
  name                = "Configure-Logic-Apps-Latest-TLS"
  display_name        = "Configure Logic apps to use the latest TLS version"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Periodically, newer versions are released for TLS either due to security flaws, include additional functionality, and enhance speed. Upgrade to the latest TLS version for Logic Apps to take advantage of security fixes and new functionalities."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category  = "Logic Apps",
    source    = "https://github.com/Azure/Enterprise-Scale/",
    version   = "1.0.0"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy",
        displayName = "Effect"
      },
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ],
      defaultValue = "DeployIfNotExists"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field   = "type",
          equals  = "Microsoft.Web/sites"
        },
        {
          field   = "kind",
          contains = "workflowapp"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]",
      details = {
        type = "Microsoft.Web/sites/config",
        name = "web",
        roleDefinitionIds = [
          "/providers/microsoft.authorization/roleDefinitions/de139f84-1756-47ae-9be6-808fbbe84772"
        ],
        existenceCondition = {
          field  = "Microsoft.Web/sites/config/minTlsVersion",
          equals = "1.2"
        },
        deployment = {
          properties = {
            mode = "incremental",
            parameters = {
              siteName = {
                value = "[field('name')]"
              }
            },
            template = {
              "$schema" = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
              contentVersion = "1.0.0.0",
              parameters = {
                siteName = {
                  type = "string"
                }
              },
              resources = [
                {
                  type = "Microsoft.Web/sites/config",
                  apiVersion = "2021-02-01",
                  name = "[concat(parameters('siteName'), '/web')]",
                  properties = {
                    minTlsVersion = "1.2"
                  }
                }
              ],
              outputs = {},
              variables = {}
            }
          }
        }
      }
    }
  })
}
#corp-Deploy a default budget on all subscriptions under the assigned scope
resource "azurerm_policy_definition" "deploy_default_budget" {
  name                = "Deploy-Budget"
  display_name        = "Deploy a default budget on all subscriptions under the assigned scope"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Deploy a default budget on all subscriptions under the assigned scope"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureUSGovernment"
    ],
    category  = "Budget",
    source    = "https://github.com/Azure/Enterprise-Scale/",
    version   = "1.1.0"
  })

  parameters = jsonencode({
    amount = {
      type = "String",
      metadata = {
        description = "The total amount of cost or usage to track with the budget"
      },
      defaultValue = "1000"
    },
    budgetName = {
      type = "String",
      metadata = {
        description = "The name for the budget to be created"
      },
      defaultValue = "budget-set-by-policy"
    },
    contactEmails = {
      type = "Array",
      metadata = {
        description = "The list of email addresses, in an array, to send the budget notification to when the threshold is exceeded."
      },
      defaultValue = []
    },
    contactGroups = {
      type = "Array",
      metadata = {
        description = "The list of action groups, in an array, to send the budget notification to when the threshold is exceeded. It accepts array of strings."
      },
      defaultValue = []
    },
    contactRoles = {
      type = "Array",
      metadata = {
        description = "The list of contact RBAC roles, in an array, to send the budget notification to when the threshold is exceeded."
      },
      defaultValue = [
        "Owner",
        "Contributor"
      ]
    },
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy"
      },
      allowedValues = [
        "DeployIfNotExists",
        "AuditIfNotExists",
        "Disabled"
      ],
      defaultValue = "DeployIfNotExists"
    },
    firstThreshold = {
      type = "String",
      metadata = {
        description = "Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000."
      },
      defaultValue = "90"
    },
    secondThreshold = {
      type = "String",
      metadata = {
        description = "Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000."
      },
      defaultValue = "100"
    },
    timeGrain = {
      type = "String",
      metadata = {
        description = "The time covered by a budget. Tracking of the amount will be reset based on the time grain."
      },
      allowedValues = [
        "Monthly",
        "Quarterly",
        "Annually",
        "BillingMonth",
        "BillingQuarter",
        "BillingAnnual"
      ],
      defaultValue = "Monthly"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "equals" = "Microsoft.Resources/subscriptions",
          "field"  = "type"
        }
      ]
    },
    "then" = {
      "details" = {
        "deployment" = {
          "location" = "northeurope",
          "properties" = {
            "mode" = "Incremental",
            "parameters" = {
              "amount" = {
                "value" = "[parameters('amount')]"
              },
              "budgetName" = {
                "value" = "[parameters('budgetName')]"
              },
              "contactEmails" = {
                "value" = "[parameters('contactEmails')]"
              },
              "contactGroups" = {
                "value" = "[parameters('contactGroups')]"
              },
              "contactRoles" = {
                "value" = "[parameters('contactRoles')]"
              },
              "firstThreshold" = {
                "value" = "[parameters('firstThreshold')]"
              },
              "secondThreshold" = {
                "value" = "[parameters('secondThreshold')]"
              },
              "timeGrain" = {
                "value" = "[parameters('timeGrain')]"
              }
            },
            "template" = {
              "$schema" = "http://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json",
              "contentVersion" = "1.0.0.0",
              "parameters" = {
                "amount" = {
                  "type" = "String"
                },
                "budgetName" = {
                  "type" = "String"
                },
                "contactEmails" = {
                  "type" = "Array"
                },
                "contactGroups" = {
                  "type" = "Array"
                },
                "contactRoles" = {
                  "type" = "Array"
                },
                "firstThreshold" = {
                  "type" = "String"
                },
                "secondThreshold" = {
                  "type" = "String"
                },
                "startDate" = {
                  "defaultValue" = "[concat(utcNow('MM'), '/01/', utcNow('yyyy'))]",
                  "type" = "String"
                },
                "timeGrain" = {
                  "type" = "String"
                }
              },
              "resources" = [
                {
                  "apiVersion" = "2019-10-01",
                  "name" = "[parameters('budgetName')]",
                  "properties" = {
                    "amount" = "[parameters('amount')]",
                    "category" = "Cost",
                    "notifications" = {
                      "NotificationForExceededBudget1" = {
                        "contactEmails" = "[parameters('contactEmails')]",
                        "contactGroups" = "[parameters('contactGroups')]",
                        "contactRoles" = "[parameters('contactRoles')]",
                        "enabled" = true,
                        "operator" = "GreaterThan",
                        "threshold" = "[parameters('firstThreshold')]"
                      },
                      "NotificationForExceededBudget2" = {
                        "contactEmails" = "[parameters('contactEmails')]",
                        "contactGroups" = "[parameters('contactGroups')]",
                        "contactRoles" = "[parameters('contactRoles')]",
                        "enabled" = true,
                        "operator" = "GreaterThan",
                        "threshold" = "[parameters('secondThreshold')]"
                      }
                    },
                    "timeGrain" = "[parameters('timeGrain')]",
                    "timePeriod" = {
                      "startDate" = "[parameters('startDate')]"
                    }
                  },
                  "type" = "Microsoft.Consumption/budgets"
                }
              ]
            }
          }
        },
        "deploymentScope" = "subscription",
        "existenceCondition" = {
          "allOf" = [
            {
              "equals" = "[parameters('amount')]",
              "field"  = "Microsoft.Consumption/budgets/amount"
            },
            {
              "equals" = "[parameters('timeGrain')]",
              "field"  = "Microsoft.Consumption/budgets/timeGrain"
            },
            {
              "equals" = "Cost",
              "field"  = "Microsoft.Consumption/budgets/category"
            }
          ]
        },
        "existenceScope" = "subscription",
        "roleDefinitionIds" = [
          "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
        ],
        "type" = "Microsoft.Consumption/budgets"
      },
      "effect" = "[parameters('effect')]"
    }
 })
}
#corp-Deploy SQL Database Vulnerability Assessments
resource "azurerm_policy_definition" "deploy_sql_database_auditing_settings" {
  name                = "Deploy-Sql-AuditingSettings"
  display_name        = "Deploy SQL database auditing settings"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Deploy auditing settings to SQL Database when it does not exist in the deployment."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "SQL",
    version  = "1.0.0",
    source   = "https://github.com/Azure/Enterprise-Scale/"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy"
        displayName = "Effect"
      },
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ],
      defaultValue = "DeployIfNotExists"
    }
  })

  policy_rule = jsonencode({
    if = {
      field  = "type",
      equals = "Microsoft.Sql/servers/databases"
    },
    then = {
      details = {
        deployment = {
          properties = {
            mode = "Incremental",
            parameters = {
              location = {
                value = "[field('location')]"
              },
              sqlServerDataBaseName = {
                value = "[field('name')]"
              },
              sqlServerName = {
                value = "[first(split(field('fullname'),'/'))]"
              }
            },
            template = {
              "$schema" = "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
              contentVersion = "1.0.0.0",
              outputs = {},
              parameters = {
                location = {
                  type = "String"
                },
                sqlServerDataBaseName = {
                  type = "String"
                },
                sqlServerName = {
                  type = "String"
                }
              },
              resources = [
                {
                  apiVersion = "2017-03-01-preview",
                  name = "[concat(parameters('sqlServerName'),'/',parameters('sqlServerDataBaseName'),'/default')]",
                  type = "Microsoft.Sql/servers/databases/auditingSettings",
                  properties = {
                    auditActionsAndGroups = [
                      "BATCH_COMPLETED_GROUP",
                      "DATABASE_OBJECT_CHANGE_GROUP",
                      "SCHEMA_OBJECT_CHANGE_GROUP",
                      "BACKUP_RESTORE_GROUP",
                      "APPLICATION_ROLE_CHANGE_PASSWORD_GROUP",
                      "DATABASE_PRINCIPAL_CHANGE_GROUP",
                      "DATABASE_PRINCIPAL_IMPERSONATION_GROUP",
                      "DATABASE_ROLE_MEMBER_CHANGE_GROUP",
                      "USER_CHANGE_PASSWORD_GROUP",
                      "DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP",
                      "DATABASE_OBJECT_PERMISSION_CHANGE_GROUP",
                      "DATABASE_PERMISSION_CHANGE_GROUP",
                      "SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP",
                      "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP",
                      "FAILED_DATABASE_AUTHENTICATION_GROUP"
                    ],
                    isAzureMonitorTargetEnabled = true,
                    state = "enabled"
                  }
                }
              ],
              variables = {}
            }
          }
        },
        existenceCondition = {
          allOf = [
            {
              equals = "enabled",
              field  = "Microsoft.Sql/servers/databases/auditingSettings/state"
            },
            {
              equals = "true",
              field  = "Microsoft.Sql/servers/databases/auditingSettings/isAzureMonitorTargetEnabled"
            }
          ]
        },
        name = "default",
        roleDefinitionIds = [
          "/providers/Microsoft.Authorization/roleDefinitions/056cd41c-7e88-42e1-933e-88ba6a50c9c3"
        ],
        type = "Microsoft.Sql/servers/databases/auditingSettings"
      },
      effect = "[parameters('effect')]"
    }
  })
}
#corp-Deploy SQL DB security Alert Policies configuration with email admin accounts
resource "azurerm_policy_definition" "deploy_sql_security_alert_policies" {
  name                = "Deploy-Sql-SecurityAlertPolicies"
  display_name        = "Deploy SQL Database security Alert Policies configuration with email admin accounts"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Deploy the security Alert Policies configuration with email admin accounts when it does not exist in current configuration"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category = "SQL",
    source   = "https://github.com/Azure/Enterprise-Scale/",
    version  = "1.1.1"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy",
        displayName = "Effect"
      },
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ],
      defaultValue = "DeployIfNotExists"
    },
    emailAddresses = {
      type = "Array",
      defaultValue = [
        "admin@contoso.com",
        "admin@fabrikam.com"
      ]
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "equals" = "Microsoft.Sql/servers/databases",
      "field"  = "type"
    },
    "then" = {
      "details" = {
        "deployment" = {
          "properties" = {
            "mode" = "Incremental",
            "parameters" = {
              "emailAddresses" = {
                "value" = "[parameters('emailAddresses')]"
              },
              "location" = {
                "value" = "[field('location')]"
              },
              "sqlServerDataBaseName" = {
                "value" = "[field('name')]"
              },
              "sqlServerName" = {
                "value" = "[first(split(field('fullname'),'/'))]"
              }
            },
            "template" = {
              "$schema" = "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
              "contentVersion" = "1.0.0.0",
              "outputs" = {},
              "parameters" = {
                "emailAddresses" = {
                  "type" = "Array"
                },
                "location" = {
                  "type" = "String"
                },
                "sqlServerDataBaseName" = {
                  "type" = "String"
                },
                "sqlServerName" = {
                  "type" = "String"
                }
              },
              "resources" = [
                {
                  "apiVersion" = "2018-06-01-preview",
                  "name" = "[concat(parameters('sqlServerName'),'/',parameters('sqlServerDataBaseName'),'/default')]",
                  "properties" = {
                    "disabledAlerts" = [
                      ""
                    ],
                    "emailAccountAdmins" = true,
                    "emailAddresses" = "[parameters('emailAddresses')]",
                    "retentionDays" = 0,
                    "state" = "Enabled",
                    "storageAccountAccessKey" = "",
                    "storageEndpoint" = null
                  },
                  "type" = "Microsoft.Sql/servers/databases/securityAlertPolicies"
                }
              ],
              "variables" = {}
            }
          }
        },
        "existenceCondition" = {
          "allOf" = [
            {
              "equals" = "Enabled",
              "field"  = "Microsoft.Sql/servers/databases/securityAlertPolicies/state"
            }
          ]
        },
        "roleDefinitionIds" = [
          "/providers/Microsoft.Authorization/roleDefinitions/056cd41c-7e88-42e1-933e-88ba6a50c9c3"
        ],
        "type" = "Microsoft.Sql/servers/databases/securityAlertPolicies"
      },
      "effect" = "[parameters('effect')]"
    }
  })
}
#corp-Deploy Virtual Machine Auto Shutdown Schedule
resource "azurerm_policy_definition" "deploy_vm_auto_shutdown" {
  name                = "Deploy-Vm-autoShutdown"
  display_name        = "Deploy Virtual Machine Auto Shutdown Schedule"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Deploys an auto shutdown schedule to a virtual machine"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "Compute",
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "1.0.0"
  })

  parameters = jsonencode({
    EnableNotification = {
      type = "String",
      metadata = {
        description = "If notifications are enabled for this schedule (i.e. Enabled, Disabled).",
        displayName = "Send Notification before auto-shutdown"
      },
      allowedValues = [
        "Disabled",
        "Enabled"
      ],
      defaultValue = "Disabled"
    },
    NotificationEmailRecipient = {
      type = "String",
      metadata = {
        description = "Email address to be used for notification",
        displayName = "Email Address"
      },
      defaultValue = ""
    },
    NotificationWebhookUrl = {
      type = "String",
      metadata = {
        description = "A notification will be posted to the specified webhook endpoint when the auto-shutdown is about to happen.",
        displayName = "Webhook URL"
      },
      defaultValue = ""
    },
    time = {
      type = "String",
      metadata = {
        description = "Daily Scheduled shutdown time. i.e. 2300 = 11:00 PM",
        displayName = "Scheduled Shutdown Time"
      },
      defaultValue = "0000"
    },
    timeZoneId = {
      type = "String",
      metadata = {
        description = "The time zone ID (e.g. Pacific Standard time).",
        displayName = "Time zone"
      },
      defaultValue = "UTC"
    }
  })

  policy_rule = jsonencode({
    if = {
      equals = "Microsoft.Compute/virtualMachines",
      field  = "type"
    },
    then = {
      details = {
        deployment = {
          properties = {
            mode = "incremental",
            parameters = {
              EnableNotification = {
                value = "[parameters('EnableNotification')]"
              },
              NotificationEmailRecipient = {
                value = "[parameters('NotificationEmailRecipient')]"
              },
              NotificationWebhookUrl = {
                value = "[parameters('NotificationWebhookUrl')]"
              },
              location = {
                value = "[field('location')]"
              },
              time = {
                value = "[parameters('time')]"
              },
              timeZoneId = {
                value = "[parameters('timeZoneId')]"
              },
              vmName = {
                value = "[field('name')]"
              },
              vmResourceId = {
                value = "[field('id')]"
              }
            },
            template = {
              "$schema" = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
              contentVersion = "1.0.0.0",
              outputs = {},
              parameters = {
                EnableNotification = {
                  type = "string",
                  defaultValue = "",
                  metadata = {
                    description = "If notifications are enabled for this schedule (i.e. Enabled, Disabled)."
                  }
                },
                NotificationEmailRecipient = {
                  type = "string",
                  defaultValue = "",
                  metadata = {
                    description = "Email address to be used for notification"
                  }
                },
                NotificationWebhookUrl = {
                  type = "string",
                  defaultValue = "",
                  metadata = {
                    description = "A notification will be posted to the specified webhook endpoint when the auto-shutdown is about to happen."
                  }
                },
                location = {
                  type = "string"
                },
                time = {
                  type = "string",
                  defaultValue = "",
                  metadata = {
                    description = "Daily Scheduled shutdown time. i.e. 2300 = 11:00 PM"
                  }
                },
                timeZoneId = {
                  type = "string",
                  defaultValue = "",
                  metadata = {
                    description = "The time zone ID (e.g. Pacific Standard time)."
                  }
                },
                vmName = {
                  type = "string"
                },
                vmResourceId = {
                  type = "string"
                }
              },
              resources = [
                {
                  apiVersion = "2018-09-15",
                  location   = "[parameters('location')]",
                  name       = "[concat('shutdown-computevm-',parameters('vmName'))]",
                  type       = "Microsoft.DevTestLab/schedules",
                  properties = {
                    dailyRecurrence = {
                      time = "[parameters('time')]"
                    },
                    notificationSettings = {
                      emailRecipient = "[parameters('NotificationEmailRecipient')]",
                      notificationLocale = "en",
                      status = "[parameters('EnableNotification')]",
                      timeInMinutes = 30,
                      webhookUrl = "[parameters('NotificationWebhookUrl')]"
                    },
                    status = "Enabled",
                    targetResourceId = "[parameters('vmResourceId')]",
                    taskType = "ComputeVmShutdownTask",
                    timeZoneId = "[parameters('timeZoneId')]"
                  }
                }
              ],
              variables = {}
            }
          }
        },
        existenceCondition = {
          allOf = [
            {
              equals = "ComputeVmShutdownTask",
              field  = "Microsoft.DevTestLab/schedules/taskType"
            },
            {
              equals = "[field('id')]",
              field  = "Microsoft.DevTestLab/schedules/targetResourceId"
            }
          ]
        },
        roleDefinitionIds = [
          "/providers/microsoft.authorization/roleDefinitions/9980e02c-c2be-4d73-94e8-173b1dc7cf3c"
        ],
        type = "Microsoft.DevTestLab/schedules"
      },
      effect = "DeployIfNotExists"
    }
  })
}
#corp-Enable soft delete for blobs
resource "azurerm_policy_definition" "enable_soft_delete_for_blobs" {
  name                = "Deploy-Storage-Blob-SoftDelete"
  display_name        = "Enable soft delete for blobs on storage accounts"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensures that soft delete is enabled for blobs on all storage accounts."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Storage"
  })

  parameters = jsonencode({
    effect = {
      type        = "String"
      allowedValues = ["DeployIfNotExists", "Disabled"]
      defaultValue = "DeployIfNotExists"
      metadata = {
        description = "Enable or disable the execution of the policy"
        displayName = "Effect"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      field = "type"
      equals = "Microsoft.Storage/storageAccounts"
    }
    then = {
      effect = "[parameters('effect')]"
      details = {
        type = "Microsoft.Storage/storageAccounts/blobServices"
        name = "default"
        existenceCondition = {
          field = "Microsoft.Storage/storageAccounts/blobServices/deleteRetentionPolicy.enabled"
          equals = true
        }
        deployment = {
          properties = {
            mode = "incremental"
            template = {
              "$schema" = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              resources = [
                {
                  type = "Microsoft.Storage/storageAccounts/blobServices"
                  apiVersion = "2021-04-01"
                  name = "[concat(parameters('storageAccountName'), '/default')]"
                  properties = {
                    deleteRetentionPolicy = {
                      enabled = true
                      days    = 7
                    }
                  }
                }
              ]
              parameters = {
                storageAccountName = {
                  type = "string"
                }
              }
            }
            parameters = {
              storageAccountName = {
                value = "[field('name')]"
              }
            }
          }
        }
      }
    }
  })
}
#corp-Enable soft delete for containers
resource "azurerm_policy_definition" "enable_soft_delete_for_containers" {
  name                = "Deploy-Storage-Container-SoftDelete"
  display_name        = "Enable soft delete for containers on storage accounts"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensures that soft delete is enabled for containers on all storage accounts."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Storage"
  })

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["DeployIfNotExists", "Disabled"]
      defaultValue  = "DeployIfNotExists"
      metadata = {
        description = "Enable or disable the execution of the policy"
        displayName = "Effect"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      field  = "type"
      equals = "Microsoft.Storage/storageAccounts"
    }
    then = {
      effect = "[parameters('effect')]"
      details = {
        type = "Microsoft.Storage/storageAccounts/blobServices"
        name = "default"
        existenceCondition = {
          field  = "Microsoft.Storage/storageAccounts/blobServices/containerDeleteRetentionPolicy.enabled"
          equals = true
        }
        deployment = {
          properties = {
            mode = "incremental"
            template = {
              "$schema"      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              resources = [
                {
                  type       = "Microsoft.Storage/storageAccounts/blobServices"
                  apiVersion = "2021-04-01"
                  name       = "[concat(parameters('storageAccountName'), '/default')]"
                  properties = {
                    containerDeleteRetentionPolicy = {
                      enabled = true
                      days    = 7
                    }
                  }
                }
              ]
              parameters = {
                storageAccountName = {
                  type = "string"
                }
              }
            }
            parameters = {
              storageAccountName = {
                value = "[field('name')]"
              }
            }
          }
        }
      }
    }
  })
}
#corp-Enable soft delete for file shares
resource "azurerm_policy_definition" "enable_soft_delete_for_file_shares" {
  name                = "Deploy-Storage-File-SoftDelete"
  display_name        = "Enable soft delete for file shares on storage accounts"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensures that soft delete is enabled for file shares on all storage accounts."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Storage"
  })

  parameters = jsonencode({
    effect = {
      type          = "String",
      allowedValues = ["DeployIfNotExists", "Disabled"],
      defaultValue  = "DeployIfNotExists",
      metadata = {
        description = "Enable or disable the execution of the policy",
        displayName = "Effect"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      field  = "type",
      equals = "Microsoft.Storage/storageAccounts"
    },
    then = {
      effect = "[parameters('effect')]",
      details = {
        type = "Microsoft.Storage/storageAccounts/fileServices",
        name = "default",
        existenceCondition = {
          field  = "Microsoft.Storage/storageAccounts/fileServices/shareDeleteRetentionPolicy.enabled",
          equals = true
        },
        deployment = {
          properties = {
            mode = "incremental",
            template = {
              "$schema"      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
              contentVersion = "1.0.0.0",
              resources = [
                {
                  type       = "Microsoft.Storage/storageAccounts/fileServices",
                  apiVersion = "2021-04-01",
                  name       = "[concat(parameters('storageAccountName'), '/default')]",
                  properties = {
                    shareDeleteRetentionPolicy = {
                      enabled = true,
                      days    = 7
                    }
                  }
                }
              ],
              parameters = {
                storageAccountName = {
                  type = "string"
                }
              }
            },
            parameters = {
              storageAccountName = {
                value = "[field('name')]"
              }
            }
          }
        }
      }
    }
  })
}
#corp-Enforce specific configuration of Network Security Groups (NSG)
resource "azurerm_policy_definition" "modify_nsg" {
  name                = "Modify-NSG"
  display_name        = "Enforce specific configuration of Network Security Groups (NSG)"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy enforces the configuration of Network Security Groups (NSG)."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category = "Network",
    source   = "https://github.com/Azure/Enterprise-Scale/",
    version  = "1.0.0"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy",
        displayName = "Effect"
      },
      allowedValues = [
        "Modify",
        "Disabled"
      ],
      defaultValue = "Modify"
    },
    nsgRuleAccess = {
      type = "String",
      allowedValues = [
        "Allow",
        "Deny"
      ],
      defaultValue = "Deny"
    },
    nsgRuleDescription = {
      type = "String",
      defaultValue = "Deny any outbound traffic to the Internet"
    },
    nsgRuleDestinationAddressPrefix = {
      type = "String",
      defaultValue = "Internet"
    },
    nsgRuleDestinationPortRange = {
      type = "String",
      defaultValue = "*"
    },
    nsgRuleDirection = {
      type = "String",
      allowedValues = [
        "Inbound",
        "Outbound"
      ],
      defaultValue = "Outbound"
    },
    nsgRuleName = {
      type = "String",
      defaultValue = "DenyAnyInternetOutbound"
    },
    nsgRulePriority = {
      type = "Integer",
      defaultValue = 1000
    },
    nsgRuleProtocol = {
      type = "String",
      defaultValue = "*"
    },
    nsgRuleSourceAddressPrefix = {
      type = "String",
      defaultValue = "*"
    },
    nsgRuleSourcePortRange = {
      type = "String",
      defaultValue = "*"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "equals" = "Microsoft.Network/networkSecurityGroups",
          "field"  = "type"
        },
        {
          "count" = {
            "field" = "Microsoft.Network/networkSecurityGroups/securityRules[*]"
          },
          "equals" = 0
        }
      ]
    },
    "then" = {
      "details" = {
        "conflictEffect" = "audit",
        "operations" = [
          {
            "field"     = "Microsoft.Network/networkSecurityGroups/securityRules[*]",
            "operation" = "add",
            "value" = {
              "name" = "[parameters('nsgRuleName')]",
              "properties" = {
                "access"                  = "[parameters('nsgRuleAccess')]",
                "description"             = "[parameters('nsgRuleDescription')]",
                "destinationAddressPrefix"= "[parameters('nsgRuleDestinationAddressPrefix')]",
                "destinationPortRange"    = "[parameters('nsgRuleDestinationPortRange')]",
                "direction"               = "[parameters('nsgRuleDirection')]",
                "priority"                = "[parameters('nsgRulePriority')]",
                "protocol"                = "[parameters('nsgRuleProtocol')]",
                "sourceAddressPrefix"     = "[parameters('nsgRuleSourceAddressPrefix')]",
                "sourcePortRange"         = "[parameters('nsgRuleSourcePortRange')]"
              }
            }
          }
        ],
        "roleDefinitionIds" = [
          "/providers/microsoft.authorization/roleDefinitions/4d97b98b-1d4f-4787-a291-c67834d212e7"
        ]
      },
      "effect" = "[parameters('effect')]"
    }
  })
}
#corp-Ensure a Managed Identity is used for interactions with other Azure services
resource "azurerm_policy_definition" "managed_identity_used_for_azure_services" {
  name                = "Managed-Identity-Used-For-Azure-Services"
  display_name        = "Ensure a Managed Identity is used for interactions with other Azure services"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "This policy ensures that resources like Virtual Machines, Container Instances, and App Services use Managed Identities for accessing other Azure resources."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "anyOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Web/sites"
        },
        {
          "field"  = "type",
          "equals" = "Microsoft.Compute/virtualMachines"
        },
        {
          "field"  = "type",
          "equals" = "Microsoft.ContainerInstance/containerGroups"
        },
        {
          "field"  = "type",
          "equals" = "Microsoft.ManagedIdentity/userAssignedIdentities"
        }
      ]
    },
    "then" = {
      "effect" = "auditIfNotExists",
      "details" = {
        "type" = "Microsoft.ManagedIdentity/userAssignedIdentities",
        "existenceCondition" = {
          "field" = "identity.type",
          "in" = [
            "SystemAssigned",
            "UserAssigned",
            "SystemAssigned, UserAssigned"
          ]
        }
      }
    }
  })
}
#corp-Ensure an Azure Bastion Host Exists
resource "azurerm_policy_definition" "azure_bastion_host_exists" {
  name                = "Azure-Bastion-Host-Exists"
  display_name        = "Ensure an Azure Bastion Host Exists"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Manual control: Ensure an Azure Bastion Host exists in the virtual network. This policy is for documentation and compliance tracking only."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Network"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "field"  = "type",
      "equals" = "Microsoft.Network/virtualNetworks"
    },
    "then" = {
      "effect" = "Manual"
    }
  })
}
#corp-Ensure Application Insights are Configured
resource "azurerm_policy_definition" "app_insights_configured" {
  name                = "App-Insights-Configured"
  display_name        = "Ensure Application Insights are Configured"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "This policy audits Azure App Services that do not have Application Insights or any diagnostic extension configured. It ensures that telemetry collection is enabled."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Monitoring"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Web/sites"
        },
        {
          "anyOf" = [
            {
              "field"     = "Microsoft.Web/sites/siteConfig.appSettings[*].name",
              "notEquals" = "APPINSIGHTS_INSTRUMENTATIONKEY"
            },
            {
              "field"     = "Microsoft.Web/sites/siteConfig.appSettings[*].name",
              "notEquals" = "APPLICATIONINSIGHTS_CONNECTION_STRING"
            }
          ]
        }
      ]
    },
    "then" = {
      "effect" = "audit"
    }
  })
}
#corp-Ensure Azure Key Vaults are Used to Store Secrets
resource "azurerm_policy_definition" "key_vaults_used_to_store_secrets" {
  name                = "Key-Vaults-Used-To-Store-Secrets"
  display_name        = "Ensure Azure Key Vaults are Used to Store Secrets"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Audits resources to ensure that secrets are stored in Azure Key Vault and not in other less secure locations."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Security"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      field = "type",
      in = [
        "Microsoft.Web/sites",
        "Microsoft.Compute/virtualMachines",
        "Microsoft.Sql/servers",
        "Microsoft.Storage/storageAccounts"
      ]
    },
    then = {
      effect = "auditIfNotExists",
      details = {
        type = "Microsoft.KeyVault/vaults",
        existenceCondition = {
          field  = "Microsoft.Web/sites/hostNameSslStates[*].sslState",
          exists = "true"
        }
      }
    }
  })
}
#corp-Ensure Azure Resource Manager Delete locks are applied to Azure Storage Accounts
resource "azurerm_policy_definition" "arm_delete_locks_storage_accounts" {
  name                = "ARM-Delete-Locks-Storage-Accounts"
  display_name        = "Ensure Azure Resource Manager Delete locks are applied to Azure Storage Accounts"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure Azure Resource Manager Delete locks are applied to Azure Storage Accounts"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Storage"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field     = "Microsoft.Storage/storageAccounts/sku.name",
          notEquals = "Premium"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#corp-Ensure Azure Resource Manager ReadOnly locks are considered for Storage Accounts
resource "azurerm_policy_definition" "readonly_locks_storage_accounts" {
  name                = "ReadOnly-Locks-Storage-Accounts"
  display_name        = "Ensure Azure Resource Manager ReadOnly locks are considered for Azure Storage Accounts"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure Azure Resource Manager ReadOnly locks are considered for Azure Storage Accounts"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Storage"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Storage/storageAccounts"
        },
        {
          "field"     = "Microsoft.Storage/storageAccounts/sku.name",
          "notEquals" = "Premium"
        }
      ]
    },
    "then" = {
      "effect" = "[parameters('effect')]"
    }
  })
}
#corp-Ensure fewer than 5 users have global administrator assignment
resource "azurerm_policy_definition" "fewer_than_5_global_admins" {
  name                = "Fewer-Than-5-Global-Admins"
  display_name        = "Ensure fewer than 5 users have global administrator assignment"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure fewer than 5 users have global administrator assignments."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "field"  = "Microsoft.Authorization/roleAssignments/roleDefinitionId",
      "equals" = "/providers/Microsoft.Authorization/roleDefinitions/{globalAdminRoleId}"
    },
    "then" = {
      "effect" = "audit"
    }
  })
}
#corp-Ensure locked immutability policies are used for containers storing business critical blob data
resource "azurerm_policy_definition" "locked_immutability_policy_blob" {
  name                = "Locked-Immutability-Policy-Blob"
  display_name        = "Ensure locked immutability policies are used for containers storing business-critical blob data"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure locked immutability policies are used for containers storing business-critical blob data"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Storage"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field     = "Microsoft.Storage/storageAccounts/immutableStorageWithVersioning.enabled",
          notEquals = "true"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#corp-Ensure 'Microsoft Entra Authentication' is 'Enabled'
resource "azurerm_policy_definition" "entra_authentication_enabled"  {
  name                = "Entra-Authentication-Enabled"
  display_name        = "Ensure 'Microsoft Entra Authentication' is 'Enabled'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure 'Microsoft Entra Authentication' is 'Enabled'"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Cache/Redis"
        },
        {
          "field"  = "Microsoft.Cache/Redis/sslPort",
          "exists" = "false"
        }
      ]
    },
    "then" = {
      "effect" = "[parameters('effect')]"
    }
  })
}
#corp-Ensure Multi factor Authentication is Required for Risky Sign ins
resource "azurerm_policy_definition" "mfa_required_risky_signins" {
  name                = "MFA-Required-Risky-Signins"
  display_name        = "Ensure Multi-factor Authentication is Required for Risky Sign-ins"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy audits to ensure Multi-factor Authentication is required for risky sign-ins (Manual)."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Authorization/policyAssignments"
        },
        {
          "field"  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          "equals" = "/providers/Microsoft.Authorization/policyDefinitions/signInRisk"
        }
      ]
    },
    "then" = {
      "effect" = "Audit"
    }
  })
}
#corp-Ensure Multi factor Authentication is Required to access Microsoft Admin Portals
resource "azurerm_policy_definition" "mfa_required_admin_portals" {
  name                = "MFA-Required-Admin-Portals"
  display_name        = "Ensure Multi-factor Authentication is Required to access Microsoft Admin Portals"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy audits if MFA is required for admin portals."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Authorization/policyAssignments"
        },
        {
          "field"  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          "equals" = "/providers/Microsoft.Authorization/policyDefinitions/RequireMFAForAdmins"
        }
      ]
    },
    "then" = {
      "effect" = "Audit"
    }
  })
}
#corp-Ensure only MFA enabled identities can access privileged Virtual Machine
resource "azurerm_policy_definition" "mfa_enabled_identities_vm_access" {
  name                = "MFA-Enabled-Identities-VM-Access"
  display_name        = "Ensure only MFA enabled identities can access privileged Virtual Machine"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy audits role assignments made to user principals. It is recommended that these identities have MFA enforced via Conditional Access."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Identity & Access"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Authorization/roleAssignments"
        },
        {
          "field"  = "Microsoft.Authorization/roleAssignments/principalType",
          "equals" = "User"
        }
      ]
    },
    "then" = {
      "effect" = "audit"
    }
  })
}
#corp-Ensure Security Defaults is enabled on Microsoft Entra ID
resource "azurerm_policy_definition" "security_defaults_enabled" {
  name                = "Security-Defaults-Enabled"
  display_name        = "Ensure Security Defaults is enabled on Microsoft Entra ID"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy ensures that Security Defaults are enabled on Microsoft Entra ID."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Authorization/policyAssignments"
        },
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "/providers/Microsoft.Authorization/policyDefinitions/securityDefaults"
        },
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "Disabled"
        }
      ]
    },
    then = {
      effect = "audit"
    }
  })
}
#corp-Ensure server parameter 'audit log enabled' is set to 'ON' for MySQL DB
resource "azurerm_policy_definition" "audit_log_enabled_mysql" {
  name                = "Audit-Log-Enabled-MySQL"
  display_name        = "Ensure server parameter 'audit_log_enabled' is set to 'ON' for MySQL Database Server"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy ensures that the server parameter 'audit_log_enabled' is set to 'ON' for MySQL Database Servers to capture auditing data."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Database"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.DBforMySQL/servers"
        },
        {
          "field"     = "Microsoft.DBforMySQL/servers/sku.name",
          "notEquals" = "GeneralPurpose"
        }
      ]
    },
    "then" = {
      "effect" = "[parameters('effect')]"
    }
  })
}
#corp-Ensure server parameter 'audit log events' has 'CONNECTION' set for MySQL flexible server
resource "azurerm_policy_definition" "audit_log_events_connection_mysql" {
  name                = "Audit-Log-Events-Connection-MySQL"
  display_name        = "Ensure server parameter 'audit_log_events' has 'CONNECTION' set for MySQL flexible server"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure server parameter 'audit_log_events' has 'CONNECTION' set for MySQL flexible server"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Database"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.DBforMySQL/flexibleServers"
        },
        {
          field  = "Microsoft.DBforMySQL/flexibleServers/sslEnforcement",
          equals = "Disabled"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#corp-Ensure server parameter 'logfiles.retention days' is greater than 3 days for PostgreSQL flexible server
resource "azurerm_policy_definition" "logfiles_retention_days_postgresql" {
  name                = "Logfiles-Retention-Days-PostgreSQL"
  display_name        = "Ensure server parameter 'logfiles.retention_days' is greater than 3 days for PostgreSQL flexible server"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Manual control: Ensure server parameter 'logfiles.retention_days' is greater than 3 days for PostgreSQL flexible server. No Azure Policy alias currently exists for this setting, so this policy is for documentation and compliance tracking only."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "PostgreSQL"
  })

  parameters = jsonencode({})

  # No valid Azure Policy alias exists for this setting, so the policy rule only audits existence for documentation.
  policy_rule = jsonencode({
    if = {
      field  = "type",
      equals = "Microsoft.DBforPostgreSQL/flexibleServers"
    },
    then = {
      effect = "Manual"
    }
  })
}
#corp-Ensure server parameter 'require secure transport' is set to 'ON' for MySQL flexible server
resource "azurerm_policy_definition" "require_secure_transport_mysql" {
  name                = "Require-Secure-Transport-MySQL"
  display_name        = "Ensure server parameter 'require_secure_transport' is set to 'ON' for MySQL flexible server"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Manual control: Ensure 'require_secure_transport' is set to 'ON' for MySQL flexible servers. No Azure Policy alias currently exists for this setting, so this policy is for documentation and compliance tracking only."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Database"
  })

  parameters = jsonencode({})

  # No valid Azure Policy alias exists for this setting, so the policy rule only audits existence for documentation.
  policy_rule = jsonencode({
    if = {
      field  = "type",
      equals = "Microsoft.DBforMySQL/flexibleServers"
    },
    then = {
      effect = "Manual"
    }
  })
}
#corp-Ensure server parameter 'tls version' is set to 'TLSv1.2' (or higher) for MySQL flexible server
resource "azurerm_policy_definition" "tls_version_mysql_flexible_server" {
  name                = "TLS-Version-MySQL-Flexible-Server"
  display_name        = "Ensure server parameter 'tls_version' is set to 'TLSv1.2' (or higher) for MySQL flexible server"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Enforces that the 'tls_version' parameter is set to 'TLSv1.2' or higher to ensure secure communication with the MySQL Flexible Server."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Security"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      field  = "type",
      equals = "Microsoft.DBforMySQL/flexibleServers"
    },
    then = {
      effect = "deployIfNotExists",
      details = {
        type = "Microsoft.DBforMySQL/flexibleServers/configurations",
        name = "tls_version",
        roleDefinitionIds = [
          "/providers/Microsoft.Authorization/roleDefinitions/8a1b3204-d7f0-4a3c-9f9e-8c118f51a92c"
        ],
        deployment = {
          properties = {
            mode = "incremental",
            template = {
              "$schema" = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
              contentVersion = "1.0.0.0",
              parameters = {
                serverName = {
                  type = "string"
                },
                location = {
                  type = "string"
                }
              },
              resources = [
                {
                  type = "Microsoft.DBforMySQL/flexibleServers/configurations",
                  apiVersion = "2021-05-01",
                  name = "[concat(parameters('serverName'), '/tls_version')]",
                  location = "[parameters('location')]",
                  properties = {
                    value = "TLSv1.2",
                    source = "user-override"
                  }
                }
              ]
            },
            parameters = {
              serverName = {
                value = "[field('name')]"
              },
              location = {
                value = "[field('location')]"
              }
            }
          }
        }
      }
    }
  })
}
#corp-Ensure 'SMB channel encryption' is set to 'AES 256 GCM' or higher for SMB file shares
resource "azurerm_policy_definition" "smb_channel_encryption_aes256gcm" {
  name                = "SMB-Channel-Encryption-AES256GCM"
  display_name        = "Ensure 'SMB channel encryption' is set to 'AES-256-GCM' or higher for SMB file shares"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Audit file services that do not use AES-256-GCM for SMB channel encryption."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Storage"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Storage/storageAccounts/fileServices"
        },
        {
          "field"     = "Microsoft.Storage/storageAccounts/fileServices/protocolSettings.smb.channelEncryption",
          "notEquals" = "AES-256-GCM"
        }
      ]
    },
    "then" = {
      "effect" = "audit"
    }
  })
}
#corp-Ensure Soft Delete is Enabled for Azure Containers and Blob Storage
resource "azurerm_policy_definition" "soft_delete_enabled_blob_storage" {
  name                = "Soft-Delete-Enabled-Blob-Storage"
  display_name        = "Ensure Soft Delete is Enabled for Azure Containers and Blob Storage"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Audits blob services under storage accounts that do not have soft delete enabled or configured properly."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.3",
    category = "Storage"
  })

  parameters = jsonencode({
    minimumRetentionDays = {
      type = "Integer",
      metadata = {
        displayName = "Minimum Retention Days",
        description = "Minimum number of days for soft delete retention",
        strongType = "Integer"
      },
      defaultValue = 7
    }
  })

  policy_rule = jsonencode({
    if = {
      anyOf = [
        {
          field  = "type",
          equals = "Microsoft.Storage/storageAccounts/blobServices"
        }
      ]
    },
    then = {
      effect = "auditIfNotExists",
      details = {
        type = "Microsoft.Storage/storageAccounts/blobServices",
        existenceCondition = {
          anyOf = [
            {
              field     = "Microsoft.Storage/storageAccounts/blobServices/deleteRetentionPolicy.enabled",
              notEquals = true
            },
            {
              allOf = [
                {
                  field  = "Microsoft.Storage/storageAccounts/blobServices/deleteRetentionPolicy.enabled",
                  equals = true
                },
                {
                  field = "Microsoft.Storage/storageAccounts/blobServices/deleteRetentionPolicy.days",
                  less  = "[parameters('minimumRetentionDays')]"
                }
              ]
            },
            {
              field     = "Microsoft.Storage/storageAccounts/blobServices/containerDeleteRetentionPolicy.enabled",
              notEquals = true
            },
            {
              allOf = [
                {
                  field  = "Microsoft.Storage/storageAccounts/blobServices/containerDeleteRetentionPolicy.enabled",
                  equals = true
                },
                {
                  field = "Microsoft.Storage/storageAccounts/blobServices/containerDeleteRetentionPolicy.days",
                  less  = "[parameters('minimumRetentionDays')]"
                }
              ]
            }
          ]
        }
      }
    }
  })
}
#corp-Ensure that a Custom Bad Password List is set to 'Enforce' for your Organization
resource "azurerm_policy_definition" "custom_bad_password_list_enforce" {
  name                = "Custom-Bad-Password-List-Enforce"
  display_name        = "Ensure that a Custom Bad Password List is set to 'Enforce' for your Organization"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy audits if the custom bad password list is not set to 'Enforce' in Microsoft Entra password protection settings. Manual remediation is required."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Authorization/policyAssignments"
        },
        {
          "field"  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          "equals" = "/providers/Microsoft.Authorization/policyDefinitions/customBadPasswordListEnforcementState"
        }
      ]
    },
    "then" = {
      "effect" = "Audit"
    }
  })
}
#corp-Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs
resource "azurerm_policy_definition" "diagnostic_setting_subscription_activity_logs" {
  name                = "Diagnostic-Setting-Subscription-Activity-Logs"
  display_name        = "Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Audits subscriptions that do not have a diagnostic setting configured to export Activity Logs to Log Analytics, Event Hub, or Storage Account."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Monitoring"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "field"  = "type",
      "equals" = "Microsoft.Resources/subscriptions"
    },
    "then" = {
      "effect" = "auditIfNotExists",
      "details" = {
        "type" = "Microsoft.Insights/diagnosticSettings",
        "existenceCondition" = {
          "anyOf" = [
            {
              "field"  = "Microsoft.Insights/diagnosticSettings/logs.enabled",
              "equals" = true
            },
            {
              "field"  = "Microsoft.Insights/diagnosticSettings/metrics.enabled",
              "equals" = true
            }
          ]
        }
      }
    }
  })
}
#corp-Ensure that A Multi factor Authentication Policy Exists for Administrative Groups
resource "azurerm_policy_definition" "mfa_policy_admin_groups" {
  name                = "MFA-Policy-Admin-Groups"
  display_name        = "Ensure that A Multi-factor Authentication Policy Exists for Administrative Groups"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensures that MFA is enabled for all administrative groups."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Authorization/roleAssignments"
        },
        {
          "field" = "Microsoft.Authorization/roleAssignments/roleDefinitionId",
          "in" = [
            "/providers/Microsoft.Authorization/roleDefinitions/{roleId1}",
            "/providers/Microsoft.Authorization/roleDefinitions/{roleId2}"
          ]
        }
      ]
    },
    "then" = {
      "effect" = "audit"
    }
  })
}
#corp-Ensure that account 'Lockout duration in seconds' is greater than or equal to '60'
resource "azurerm_policy_definition" "account_lockout_duration_seconds" {
  name                = "Account-Lockout-Duration-Seconds"
  display_name        = "Ensure that account 'Lockout duration in seconds' is greater than or equal to '60'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy audits to ensure that account 'Lockout duration in seconds' is greater than or equal to '60' (Manual)."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Authorization/policyAssignments"
        },
        {
          "field" = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          "less"  = 60
        }
      ]
    },
    "then" = {
      "effect" = "Audit"
    }
  })
}
#corp-Ensure that account 'Lockout Threshold' is less than or equal to '10'
resource "azurerm_policy_definition" "account_lockout_threshold" {
  name                = "Account-Lockout-Threshold"
  display_name        = "Ensure that account 'Lockout Threshold' is less than or equal to '10'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy audits to ensure that account 'Lockout Threshold' is less than or equal to '10' (Manual)."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Authorization/policyAssignments"
        },
        {
          "field" = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          "lessOrEquals" = 10
        }
      ]
    },
    "then" = {
      "effect" = "Audit"
    }
  })
}
# corp-Ensure that 'Agentless scanning for machines' component status is set to 'On'
resource "azurerm_policy_definition" "agentless_scanning_for_machines" {
  name                = "Agentless-Scanning-For-Machines"
  display_name        = "Ensure that 'Agentless scanning for machines' component status is set to 'On'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that 'Agentless scanning for machines' component status is set to 'On'"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Security/assessments"
        },
        {
          field  = "Microsoft.Security/assessments/status.code",
          equals = "Enabled"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#corp-Ensure That 'All users with the following roles' is set to 'Owner'
resource "azurerm_policy_definition" "all_users_roles_set_to_owner" {
  name                = "All-Users-Roles-Set-To-Owner"
  display_name        = "Ensure That 'All users with the following roles' is set to 'Owner'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure That 'All users with the following roles' is set to 'Owner'"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Authorization/roleAssignments"
        },
        {
          "field"  = "Microsoft.Authorization/roleAssignments/roleDefinitionId",
          "equals" = "/subscriptions/{subscription-id}/providers/Microsoft.Authorization/roleDefinitions/{owner-role-definition-id}"
        }
      ]
    },
    "then" = {
      "effect" = "[parameters('effect')]"
    }
  })
}
# corp-Ensure that 'Enable Data Access Authentication Mode' is 'Checked'
resource "azurerm_policy_definition" "enable_data_access_auth_mode" {
  name                = "Enable-Data-Access-Authentication-Mode"
  display_name        = "Ensure that 'Enable Data Access Authentication Mode' is 'Checked'"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "This policy audits Azure Key Vaults that are not using the RBAC permission model. It helps ensure access control is managed via Azure RBAC instead of access policies."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Key Vault"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      field  = "type",
      equals = "Microsoft.KeyVault/vaults"
    },
    then = {
      effect = "auditIfNotExists",
      details = {
        type = "Microsoft.KeyVault/vaults",
        existenceCondition = {
          field  = "Microsoft.KeyVault/vaults/enableRbacAuthorization",
          equals = true
        }
      }
    }
  })
}
# corp-Ensure that 'Enable key rotation reminders' is enabled for each Storage Account
resource "azurerm_policy_definition" "enable_key_rotation_reminders" {
  name                = "Enable-Key-Rotation-Reminders"
  display_name        = "Ensure that 'Enable key rotation reminders' is enabled for each Storage Account"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "This policy ensures that 'Enable key rotation reminders' is enabled for all Storage Accounts."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Storage"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field     = "Microsoft.Storage/storageAccounts/keyPolicy.keyExpirationPeriodInDays",
          notEquals = 90
        }
      ]
    },
    then = {
      effect = "audit"
    }
  })
}
#corp-Ensure that 'Endpoint protection' component status is set to On'
resource "azurerm_policy_definition" "endpoint_protection_component_on" {
  name                = "Endpoint-Protection-Component-On"
  display_name        = "Ensure that 'Endpoint protection' component status is set to 'On'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that 'Endpoint protection' component status is set to 'On'"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Security/assessments"
        },
        {
          field  = "Microsoft.Security/assessments/status.code",
          equals = "Enabled"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#corp-Ensure that 'File Integrity Monitoring' component status is set to 'On'
resource "azurerm_policy_definition" "file_integrity_monitoring_on" {
  name                = "File-Integrity-Monitoring-On"
  display_name        = "Ensure that 'File Integrity Monitoring' component status is set to 'On'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that 'File Integrity Monitoring' component status is set to 'On'"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Security/assessments"
        },
        {
          field  = "Microsoft.Security/assessments/status.code",
          equals = "Enabled"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#corp-Ensure that HTTP(S) access from the Internet is evaluated and restricted
resource "azurerm_policy_definition" "http_https_access_from_internet_restricted" {
  name                = "HTTP-HTTPS-Access-From-Internet-Restricted"
  display_name        = "Ensure that HTTP(S) access from the Internet is evaluated and restricted"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy audits NSG rules that allow inbound HTTP or HTTPS (TCP ports 80 or 443) traffic from the Internet."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Network"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Network/networkSecurityGroups/securityRules"
        },
        {
          "field"  = "Microsoft.Network/networkSecurityGroups/securityRules/access",
          "equals" = "Allow"
        },
        {
          "field"  = "Microsoft.Network/networkSecurityGroups/securityRules/direction",
          "equals" = "Inbound"
        },
        {
          "field"  = "Microsoft.Network/networkSecurityGroups/securityRules/protocol",
          "equals" = "Tcp"
        },
        {
          "field" = "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix",
          "in"    = ["*", "Internet"]
        },
        {
          "anyOf" = [
            {
              "field" = "Microsoft.Network/networkSecurityGroups/securityRules/destinationPortRange",
              "in"    = ["80", "443"]
            },
            {
              "field" = "Microsoft.Network/networkSecurityGroups/securityRules/destinationPortRanges[*]",
              "contains" = "80"
            },
            {
              "field" = "Microsoft.Network/networkSecurityGroups/securityRules/destinationPortRanges[*]",
              "contains" = "443"
            }
          ]
        }
      ]
    },
    "then" = {
      "effect" = "audit"
    }
  })
}
#corp-Ensure that logging for Azure AppService 'HTTP logs' is enabled
resource "azurerm_policy_definition" "http_logs_enabled_appservice" {
  name                = "HTTP-Logs-Enabled-AppService"
  display_name        = "Ensure that logging for Azure AppService 'HTTP logs' is enabled"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Audits App Services where HTTP Logging (web server logging) is not enabled. This ensures access logs are available for diagnostics and compliance."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "App Service"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Web/sites"
        },
        {
          "field"     = "Microsoft.Web/sites/siteConfig.httpLoggingEnabled",
          "notEquals" = true
        }
      ]
    },
    "then" = {
      "effect" = "audit"
    }
  })
}
#corp-Ensure that Microsoft Cloud Security Benchmark policies are not set to 'Disabled'
resource "azurerm_policy_definition" "cloud_security_benchmark_not_disabled" {
  name                = "Cloud-Security-Benchmark-Not-Disabled"
  display_name        = "Ensure that Microsoft Cloud Security Benchmark policies are not set to 'Disabled'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that Microsoft Cloud Security Benchmark policies are not set to 'Disabled'"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Security/assessments"
        },
        {
          "field"  = "Microsoft.Security/assessments/status.code",
          "equals" = "Disabled"
        }
      ]
    },
    "then" = {
      "effect" = "[parameters('effect')]"
    }
  })
}
#corp-Ensure that Microsoft Defender External Attack Surface Monitoring is enabled
resource "azurerm_policy_definition" "defender_easm_enabled" {
  name                = "Defender-EASM-Enabled"
  display_name        = "Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Security/assessments"
        },
        {
          field  = "Microsoft.Security/assessments/status.code",
          equals = "Enabled"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#corp-Ensure that Microsoft Defender for Cloud Apps integration with Microsoft Defender for Cloud is Selected
resource "azurerm_policy_definition" "defender_cloud_apps_integration" {
  name                = "Defender-Cloud-Apps-Integration"
  display_name        = "Ensure that Microsoft Defender for Cloud Apps integration with Microsoft Defender for Cloud is Selected"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensures Microsoft Defender for Cloud Apps integration with Microsoft Defender for Cloud is enabled (CIS Microsoft Azure Foundations Benchmark v3.0.0 3.1.1.2)"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Security Center"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        displayName = "Effect",
        description = "Enable or disable the execution of the policy"
      },
      allowedValues = [
        "DeployIfNotExists",
        "AuditIfNotExists",
        "Disabled"
      ],
      defaultValue = "DeployIfNotExists"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Security/settings"
        },
        {
          field  = "name",
          equals = "MCAS"
        },
        {
          field     = "Microsoft.Security/settings/DataExportSettings.enabled",
          notEquals = "true"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]",
      details = {
        type = "Microsoft.Security/settings",
        existenceCondition = {
          field  = "Microsoft.Security/settings/DataExportSettings.enabled",
          equals = "true"
        },
        deployment = {
          properties = {
            mode = "incremental",
            template = {
              "$schema" = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
              contentVersion = "1.0.0.0",
              resources = [
                {
                  type       = "Microsoft.Security/settings",
                  apiVersion = "2022-01-01-preview",
                  name       = "MCAS",
                  properties = {
                    enabled     = true,
                    settingKind = "DataExportSettings"
                  }
                }
              ]
            }
          }
        }
      }
    }
  })
}
#corp-Ensure That Microsoft Defender for IoT Hub Is Set To 'On'
resource "azurerm_policy_definition" "defender_iot_hub_on" {
  name                = "Defender-IoT-Hub-On"
  display_name        = "Ensure That Microsoft Defender for IoT Hub Is Set To 'On'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensures Microsoft Defender for IoT Hub is enabled as per CIS Azure Foundations Benchmark v3.0.0"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Security Center"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        displayName = "Effect",
        description = "Enable or disable policy execution"
      },
      allowedValues = [
        "DeployIfNotExists",
        "AuditIfNotExists",
        "Disabled"
      ],
      defaultValue = "DeployIfNotExists"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Security/pricings"
        },
        {
          field  = "name",
          equals = "IoT"
        },
        {
          field     = "Microsoft.Security/pricings/pricingTier",
          notEquals = "Standard"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]",
      details = {
        type = "Microsoft.Security/pricings",
        existenceCondition = {
          allOf = [
            {
              field  = "Microsoft.Security/pricings/pricingTier",
              equals = "Standard"
            }
          ]
        },
        roleDefinitionIds = [
          "/providers/Microsoft.Authorization/roleDefinitions/fb1c8493-542b-48eb-b624-b4c8fea62acd"
        ],
        deployment = {
          properties = {
            mode = "incremental",
            template = {
              "$schema" = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
              contentVersion = "1.0.0.0",
              resources = [
                {
                  type = "Microsoft.Security/pricings",
                  apiVersion = "2023-01-01",
                  name = "IoT",
                  properties = {
                    pricingTier = "Standard"
                  }
                }
              ]
            }
          }
        }
      }
    }
  })
}
#corp-Ensure That 'Notify all admins when other admins reset their password' is set to 'Yes'
resource "azurerm_policy_definition" "notify_admins_on_password_reset" {
  name                = "Notify-Admins-On-Password-Reset"
  display_name        = "Ensure That 'Notify all admins when other admins reset their password?' is set to 'Yes'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy ensures that the setting 'Notify all admins when other admins reset their password' is enabled."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "/providers/Microsoft.Authorization/policyDefinitions/notifyAdminsOnPasswordReset"
        },
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "No"
        }
      ]
    },
    then = {
      effect = "Audit"
    }
  })
}
#corp-Ensure that 'Notify users on password resets' is set to 'Yes'
resource "azurerm_policy_definition" "notify_users_on_password_resets" {
  name                = "Notify-Users-On-Password-Resets"
  display_name        = "Ensure that 'Notify users on password resets?' is set to 'Yes'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy ensures that users are notified on password resets."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "/providers/Microsoft.Authorization/policyDefinitions/notifyOnPasswordReset"
        },
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "No"
        }
      ]
    },
    then = {
      effect = "Audit"
    }
  })
}
#corp-Ensure that Number of days before users are asked to re confirm their authentication information is not set to 0
resource "azurerm_policy_definition" "number_of_days_reconfirm_auth" {
  name                = "Number-Of-Days-Reconfirm-Auth"
  display_name        = "Ensure that Number of days before users are asked to re-confirm their authentication information is not set to 0"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy ensures that the number of days before users are asked to re-confirm their authentication information is not set to 0."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Authorization/policyAssignments"
        },
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "/providers/Microsoft.Authorization/policyDefinitions/numberOfDays"
        },
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = 0
        }
      ]
    },
    then = {
      effect = "Audit"
    }
  })
}
# corp-Ensure That 'Number of methods required to reset' is set to '2'
resource "azurerm_policy_definition" "number_of_methods_required_to_reset" {
  name                = "Number-Of-Methods-Required-To-Reset"
  display_name        = "Ensure That 'Number of methods required to reset' is set to '2'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Manual control: Ensure that the number of methods required to reset is set to 2 for enhanced security. This policy is for documentation and tracking only, as there is no Azure Policy alias for this setting."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  # No valid Azure Policy alias exists for this setting, so the policy rule only audits existence for documentation.
  policy_rule = jsonencode({
    if = {
      field  = "type",
      equals = "Microsoft.Resources/subscriptions"
    },
    then = {
      effect = "Manual"
    }
  })
}
# corp-Ensure that Public IP addresses are Evaluated on a Periodic Basis
resource "azurerm_policy_definition" "public_ip_addresses_periodic_evaluation" {
  name                = "Public-IP-Addresses-Periodic-Evaluation"
  display_name        = "Ensure that Public IP addresses are Evaluated on a Periodic Basis"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Audits all Public IP Addresses that are missing a required tag (e.g., 'reviewDate') to support periodic review of public exposure."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Network"
  })

  parameters = jsonencode({
    tagName = {
      type = "String",
      metadata = {
        description = "The name of the tag used for periodic review tracking (e.g., reviewDate or owner).",
        displayName = "Required Tag Name"
      },
      defaultValue = "reviewDate"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Network/publicIPAddresses"
        },
        {
          "field"  = "[concat('tags[', parameters('tagName'), ']')]",
          "exists" = "false"
        }
      ]
    },
    "then" = {
      "effect" = "audit"
    }
  })
}
#corp-Ensure that Register with Azure Active Directory is enabled on App Service
resource "azurerm_policy_definition" "register_with_aad_enabled_app_service" {
  name                = "Register-With-AAD-Enabled-App-Service"
  display_name        = "Ensure that Register with Azure Active Directory is enabled on App Service"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "This policy audits deployments of App Services that do not contain an authSettings block, which is required to register with Azure AD."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "App Service"
  })

  parameters = jsonencode({
    authConfiguredDeploymentNamePattern = {
      type = "String",
      metadata = {
        description = "Pattern for deployment names that include auth settings (e.g., AAD)",
        displayName = "Auth-Configured Deployment Name Pattern"
      },
      defaultValue = "auth*"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Resources/deployments"
        },
        {
          "field"    = "name",
          "notLike"  = "[parameters('authConfiguredDeploymentNamePattern')]"
        }
      ]
    },
    "then" = {
      "effect" = "audit"
    }
  })
}
# corp-Ensure that Resource Locks are set for Mission Critical Azure Resources
resource "azurerm_policy_definition" "resource_locks_mission_critical" {
  name                = "Resource-Locks-Mission-Critical"
  display_name        = "Ensure that Resource Locks are set for Mission-Critical Azure Resources"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Audits resources that are not tagged as mission-critical. Used to manually cross-check with resource locks."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "CIS",
    version  = "1.0.0"
  })

  parameters = jsonencode({
    tagName = {
      type = "String",
      metadata = {
        displayName = "Tag Name",
        description = "Name of the tag to identify critical resources"
      },
      defaultValue = "critical"
    },
    tagValue = {
      type = "String",
      metadata = {
        displayName = "Tag Value",
        description = "Value of the tag to identify critical resources"
      },
      defaultValue = "true"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"     = "[concat('tags[', parameters('tagName'), ']')]",
          "notEquals" = "[parameters('tagValue')]"
        }
      ]
    },
    "then" = {
      "effect" = "audit"
    }
  })
}
#corp-Ensure That 'Restrict access to Microsoft Entra admin center' is Set to 'Yes'
resource "azurerm_policy_definition" "restrict_access_entra_admin_center" {
  name                = "Restrict-Access-Entra-Admin-Center"
  display_name        = "Ensure That 'Restrict access to Microsoft Entra admin center' is Set to 'Yes'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy audits if access to the Microsoft Entra admin center is not restricted. Manual remediation is required."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Security"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Authorization/policyAssignments"
        },
        {
          "field"  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          "equals" = "/providers/Microsoft.Authorization/policyDefinitions/adminCenterAccess"
        }
      ]
    },
    "then" = {
      "effect" = "Audit"
    }
  })
}
#corp-Ensure that 'Restrict user ability to access groups features in the Access Pane' is Set to 'Yes'
resource "azurerm_policy_definition" "restrict_access_groups_features_access_pane" {
  name                = "Restrict-Access-Groups-Features-Access-Pane"
  display_name        = "Ensure that 'Restrict user ability to access groups features in the Access Pane' is Set to 'Yes'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy audits if user ability to access groups features in the Access Pane is not restricted. Manual remediation is required."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Authorization/policyAssignments"
        },
        {
          "field"  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          "equals" = "/providers/Microsoft.Authorization/policyDefinitions/effect"
        }
      ]
    },
    "then" = {
      "effect" = "Audit"
    }
  })
}
#corp-Ensure that Shared Access Signature Tokens Expire Within an Hour
resource "azurerm_policy_definition" "sas_tokens_expire_within_hour" {
  name                = "SAS-Tokens-Expire-Within-Hour"
  display_name        = "Ensure that Shared Access Signature Tokens Expire Within an Hour"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy reminds users to set Shared Access Signature tokens to expire within one hour. Due to platform limitations, this must be enforced through manual review or custom automation."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Storage"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      field  = "type",
      equals = "Microsoft.Storage/storageAccounts"
    },
    then = {
      effect = "auditIfNotExists",
      details = {
        type = "Microsoft.Insights/activityLogAlerts",
        existenceCondition = {
          allOf = [
            {
              field  = "Microsoft.Insights/activityLogAlerts/condition.allOf[*].field",
              equals = "operationName"
            },
            {
              field  = "Microsoft.Insights/activityLogAlerts/condition.allOf[*].equals",
              equals = "Microsoft.Storage/storageAccounts/ListAccountSas/action"
            }
          ]
        }
      }
    }
  })
}
#corp-Ensure that Storage Account Access Keys are Periodically Regenerated
resource "azurerm_policy_definition" "storage_account_access_keys_regenerated" {
  name                = "Storage-Account-Access-Keys-Regenerated"
  display_name        = "Ensure that Storage Account Access Keys are Periodically Regenerated"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Audit Storage Accounts that do not have key expiration policy set. Enforcing key expiration helps ensure keys are regenerated periodically."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Storage"
  })

  parameters = jsonencode({
    keyExpirationDays = {
      type = "Integer",
      metadata = {
        displayName = "Maximum Key Age (Days)",
        description = "Maximum number of days access keys are allowed before they should be regenerated."
      },
      defaultValue = 90
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field     = "Microsoft.Storage/storageAccounts/keyPolicy.keyExpirationPeriodInDays",
          notEquals = "[parameters('keyExpirationDays')]"
        }
      ]
    },
    then = {
      effect = "audit"
    }
  })
}
#corp-Ensure that 'System Assigned Managed Identity' is set to 'On'
resource "azurerm_policy_definition" "system_assigned_managed_identity_on" {
  name                = "System-Assigned-Managed-Identity-On"
  display_name        = "Ensure that 'System Assigned Managed Identity' is set to 'On'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that 'System Assigned Managed Identity' is set to 'On'"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Cache/Redis"
        },
        {
          "field"     = "Microsoft.Cache/Redis/sku.name",
          "notEquals" = "Premium"
        }
      ]
    },
    "then" = {
      "effect" = "[parameters('effect')]"
    }
  })
}
#corp-Ensure that UDP access from the Internet is evaluated and restricted
resource "azurerm_policy_definition" "udp_access_from_internet_restricted" {
  name                = "UDP-Access-From-Internet-Restricted"
  display_name        = "Ensure that UDP access from the Internet is evaluated and restricted"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy audits NSG rules that allow inbound UDP traffic from the Internet. UDP should be restricted unless explicitly required."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Network"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Network/networkSecurityGroups/securityRules"
        },
        {
          "field"  = "Microsoft.Network/networkSecurityGroups/securityRules/access",
          "equals" = "Allow"
        },
        {
          "field"  = "Microsoft.Network/networkSecurityGroups/securityRules/direction",
          "equals" = "Inbound"
        },
        {
          "field"  = "Microsoft.Network/networkSecurityGroups/securityRules/protocol",
          "equals" = "Udp"
        },
        {
          "anyOf" = [
            {
              "field"  = "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix",
              "equals" = "*"
            },
            {
              "field"  = "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix",
              "equals" = "Internet"
            }
          ]
        }
      ]
    },
    "then" = {
      "effect" = "audit"
    }
  })
}
#corp-Ensure that 'Vulnerability assessment for machines' component status is set to 'On'
resource "azurerm_policy_definition" "vulnerability_assessment_for_machines" {
  name                = "Vulnerability-Assessment-For-Machines"
  display_name        = "Ensure that 'Vulnerability assessment for machines' component status is set to 'On'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that 'Vulnerability assessment for machines' component status is set to 'On'"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Audit"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Security/assessments"
        },
        {
          field     = "Microsoft.Security/assessments/status",
          notEquals = "On"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#corp-SQL managed instances deploy a specific min TLS version requirement
resource "azurerm_policy_definition" "sql_managed_instance_min_tls" {
  name                = "Deploy-SqlMi-minTLS"
  display_name        = "SQL managed instances deploy a specific min TLS version requirement."
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Deploy a specific min TLS version requirement and enforce SSL on SQL managed instances. Enables secure server to client by enforcing minimal TLS Version to secure the connection between your database server and your client applications. This configuration enforces that SSL is always enabled for accessing your database server."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category = "SQL",
    source   = "https://github.com/Azure/Enterprise-Scale/",
    version  = "1.3.0"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy minimum TLS version SQL servers",
        displayName = "Effect SQL servers"
      },
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ],
      defaultValue = "DeployIfNotExists"
    },
    minimalTlsVersion = {
      type = "String",
      metadata = {
        description = "Select version minimum TLS version SQL servers to enforce",
        displayName = "Select version for SQL server"
      },
      allowedValues = [
        "1.2",
        "1.1",
        "1.0"
      ],
      defaultValue = "1.2"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "equals" = "Microsoft.Sql/managedInstances",
          "field"  = "type"
        },
        {
          "field" = "Microsoft.Sql/managedInstances/minimalTlsVersion",
          "less"  = "[parameters('minimalTlsVersion')]"
        }
      ]
    },
    "then" = {
      "details" = {
        "deployment" = {
          "properties" = {
            "mode" = "Incremental",
            "parameters" = {
              "location" = {
                "value" = "[field('location')]"
              },
              "minimalTlsVersion" = {
                "value" = "[parameters('minimalTlsVersion')]"
              },
              "resourceName" = {
                "value" = "[field('name')]"
              }
            },
            "template" = {
              "$schema" = "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
              "contentVersion" = "1.0.0.0",
              "outputs" = {},
              "parameters" = {
                "location" = {
                  "type" = "String"
                },
                "minimalTlsVersion" = {
                  "type" = "String"
                },
                "resourceName" = {
                  "type" = "String"
                }
              },
              "resources" = [
                {
                  "apiVersion" = "2020-02-02-preview",
                  "location"   = "[parameters('location')]",
                  "name"       = "[concat(parameters('resourceName'))]",
                  "properties" = {
                    "minimalTlsVersion" = "[parameters('minimalTlsVersion')]"
                  },
                  "type" = "Microsoft.Sql/managedInstances"
                }
              ],
              "variables" = {}
            }
          }
        },
        "evaluationDelay" = "AfterProvisioningSuccess",
        "existenceCondition" = {
          "allOf" = [
            {
              "equals" = "[parameters('minimalTlsVersion')]",
              "field"  = "Microsoft.Sql/managedInstances/minimalTlsVersion"
            }
          ]
        },
        "roleDefinitionIds" = [
          "/providers/microsoft.authorization/roleDefinitions/4939a1f6-9ae0-4e48-a1e0-f2cbe897382d"
        ],
        "type" = "Microsoft.Sql/managedInstances"
      },
      "effect" = "[parameters('effect')]"
    }
  })
}
#corp-SQL servers deploys a specific min TLS version requirement
resource "azurerm_policy_definition" "deploy_sql_min_tls" {
  name                = "Deploy-SQL-minTLS"
  display_name        = "SQL servers deploys a specific min TLS version requirement."
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Deploys a specific min TLS version requirement and enforce SSL on SQL servers. Enables secure server to client by enforcing minimal TLS Version to secure the connection between your database server and your client applications. This configuration enforces that SSL is always enabled for accessing your database server."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "SQL",
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "1.2.0",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:21:10.8028366Z",
    updatedBy  = null,
    updatedOn  = null
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy minimum TLS version SQL servers",
        displayName = "Effect SQL servers"
      },
      allowedValues = [
        "DeployIfNotExists",
        "Disabled"
      ],
      defaultValue = "DeployIfNotExists"
    },
    minimalTlsVersion = {
      type = "String",
      metadata = {
        description = "Select version minimum TLS version SQL servers to enforce",
        displayName = "Select version for SQL server"
      },
      allowedValues = [
        "1.2",
        "1.1",
        "1.0"
      ],
      defaultValue = "1.2"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          equals = "Microsoft.Sql/servers",
          field  = "type"
        },
        {
          field = "Microsoft.Sql/servers/minimalTlsVersion",
          notEquals = "[parameters('minimalTlsVersion')]"
        }
      ]
    },
    then = {
      details = {
        deployment = {
          properties = {
            mode = "Incremental",
            parameters = {
              location = {
                value = "[field('location')]"
              },
              minimalTlsVersion = {
                value = "[parameters('minimalTlsVersion')]"
              },
              resourceName = {
                value = "[field('name')]"
              }
            },
            template = {
              "$schema" = "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
              contentVersion = "1.0.0.0",
              outputs = {},
              parameters = {
                location = {
                  type = "String"
                },
                minimalTlsVersion = {
                  type = "String"
                },
                resourceName = {
                  type = "String"
                }
              },
              resources = [
                {
                  apiVersion = "2019-06-01-preview",
                  location   = "[parameters('location')]",
                  name       = "[parameters('resourceName')]",
                  properties = {
                    minimalTlsVersion = "[parameters('minimalTlsVersion')]"
                  },
                  type = "Microsoft.Sql/servers"
                }
              ],
              variables = {}
            }
          }
        },
        existenceCondition = {
          allOf = [
            {
              equals = "[parameters('minimalTlsVersion')]",
              field  = "Microsoft.Sql/servers/minimalTlsVersion"
            }
          ]
        },
        name = "current",
        roleDefinitionIds = [
          "/providers/microsoft.authorization/roleDefinitions/6d8ee4ec-f05a-4a1d-8b00-a9b17e38b437"
        ],
        type = "Microsoft.Sql/servers"
      },
      effect = "[parameters('effect')]"
    }
  })
}
#prod-Additional Parameters-Do not allow deletion of specified resource and resource type
resource "azurerm_policy_definition" "denyaction_delete_resources" {
  name                = "DenyAction-DeleteResources"
  display_name        = "Do not allow deletion of specified resource and resource type"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy enables you to specify the resource and resource type that your organization can protect from accidentals deletion by blocking delete calls using the deny action effect."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

#depends_on = [
 #   azurerm_management_group.IMS-Root
#  ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "General",
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "1.0.0",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:21:29.9000301Z",
    updatedBy  = null,
    updatedOn  = null
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy",
        displayName = "Effect"
      },
      allowedValues = [
        "DenyAction",
        "Disabled"
      ],
      defaultValue = "DenyAction"
    },
    resourceName = {
      type = "String",
      metadata = {
        description = "Provide the name of the resource that you want to protect from accidental deletion.",
        displayName = "Resource Name"
      }
    },
    resourceType = {
      type = "String",
      metadata = {
        description = "Provide the resource type that you want to protect from accidental deletion.",
        displayName = "Resource Type"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          equals = "[parameters('resourceType')]",
          field  = "type"
        },
        {
          field = "name",
          like  = "[parameters('resourceName')]"
        }
      ]
    },
    then = {
      details = {
        actionNames = [
          "delete"
        ]
      },
      effect = "[parameters('effect')]"
    }
  })
}
#prod-Additional Parameters-Prod-Encryption for storage services should be enforced for Storage Accounts
resource "azurerm_policy_definition" "enforce_storage_encryption" {
  name                = "Enforce-Storage-Encryption"
  display_name        = "Encryption for storage services should be enforced for Storage Accounts"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy enables you to specify the resource and resource type that your organization can protect from accidental deletion by blocking delete calls using the deny action effect."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

#depends_on = [
 #   azurerm_management_group.IMS-Root
#  ]
  
  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category  = "General",
    source    = "https://github.com/Azure/Enterprise-Scale/",
    version   = "1.0.0"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy",
        displayName = "Effect"
      },
      allowedValues = [
        "DenyAction",
        "Disabled"
      ],
      defaultValue = "DenyAction"
    },
    resourceName = {
      type = "String",
      metadata = {
        description = "Provide the name of the resource that you want to protect from accidental deletion.",
        displayName = "Resource Name"
      }
    },
    resourceType = {
      type = "String",
      metadata = {
        description = "Provide the resource type that you want to protect from accidental deletion.",
        displayName = "Resource Type"
      }
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "equals" = "[parameters('resourceType')]",
          "field"  = "type"
        },
        {
          "field" = "name",
          "like"  = "[parameters('resourceName')]"
        }
      ]
    },
    "then" = {
      "details" = {
        "actionNames" = [
          "delete"
        ]
      },
      "effect" = "[parameters('effect')]"
    }
  })
}
#prod-Deny enabling anonymous access on individual storage containers
resource "azurerm_policy_definition" "deny_storage_account_public_access" {
  name                = "Deny-Storage-Container-Anonymous-Access"
  display_name        = "Deny enabling public access on storage accounts"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Prevents enabling public (anonymous) access on Azure Storage accounts."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

#depends_on = [
 #   azurerm_management_group.IMS-Root
#  ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Storage"
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field  = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess",
          equals = true
        }
      ]
    }
    then = {
      effect = "deny"
    }
  })
}
#prod-Deny public network access to Key Vault
resource "azurerm_policy_definition" "deny_key_vault_public_access" {
  name                = "Deny-KeyVault-Public-Network-Access"
  display_name        = "Deny public network access to Key Vault"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensures that public network access to Azure Key Vault is disabled."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

#depends_on = [
 #   azurerm_management_group.IMS-Root
#  ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Key Vault"
  })

  parameters = jsonencode({
    effect = {
      type          = "String",
      allowedValues = ["Deny", "Disabled"],
      defaultValue  = "Deny",
      metadata = {
        description = "Enable or disable the execution of the policy",
        displayName = "Effect"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.KeyVault/vaults"
        },
        {
          field  = "Microsoft.KeyVault/vaults/publicNetworkAccess",
          notEquals = "Disabled"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#prod-DenyAction implementation on Activity Logs
resource "azurerm_policy_definition" "denyaction_activity_logs" {
  name                = "DenyAction-ActivityLogs"
  display_name        = "DenyAction implementation on Activity Logs"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "This is a DenyAction implementation policy on Activity Logs."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "Monitoring",
    deprecated = false,
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "1.0.0",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:21:03.19153Z",
    updatedBy  = null,
    updatedOn  = null
  })

  policy_rule = jsonencode({
    if = {
      equals = "Microsoft.Resources/subscriptions/providers/diagnosticSettings",
      field  = "type"
    },
    then = {
      details = {
        actionNames = [
          "delete"
        ]
      },
      effect = "denyAction"
    }
  })
}
#prod-DenyAction implementation on Diagnostic Logs
resource "azurerm_policy_definition" "denyaction_diagnostic_logs" {
  name                = "DenyAction-DiagnosticLogs"
  display_name        = "DenyAction implementation on Diagnostic Logs."
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "DenyAction implementation on Diagnostic Logs."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "Monitoring",
    deprecated = false,
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "1.0.0",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:21:04.2778154Z",
    updatedBy  = null,
    updatedOn  = null
  })

  policy_rule = jsonencode({
    if = {
      equals = "Microsoft.Insights/diagnosticSettings",
      field  = "type"
    },
    then = {
      details = {
        actionNames = [
          "delete"
        ]
      },
      effect = "denyAction"
    }
  })
}
#prod-Enforce Azure DDoS Network Protection while creating vNets
resource "azurerm_policy_definition" "enforce_ddos_protection_on_vnet" {
  name                = "enforce-ddos-protection-on-vnet"
  display_name        = "Enforce Azure DDoS Network Protection on Virtual Networks"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy ensures that every Virtual Network has Azure DDoS Network Protection enabled."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Network"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        displayName = "Effect",
        description = "Enable or disable the execution of the policy"
      },
      allowedValues = [
        "Deny",
        "Audit",
        "Disabled"
      ],
      defaultValue = "Deny"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Network/virtualNetworks"
        },
        {
          "field"     = "Microsoft.Network/virtualNetworks/ddosProtectionPlan.id",
          "exists"    = "false"
        }
      ]
    },
    "then" = {
      "effect" = "[parameters('effect')]"
    }
  })
}
#prod-Enforce Virtual Network Encryption while creating vNets
resource "azurerm_policy_definition" "force_vnet_encryption" {
  name                = "Force-Virtual-Network-Encryption"
  display_name        = "Enforce Virtual Network Encryption"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy ensures that encryption is enabled on all Virtual Networks."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Network"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        displayName = "Effect",
        description = "Enable or disable the execution of the policy"
      },
      allowedValues = [
        "Deny",
        "Audit",
        "Disabled"
      ],
      defaultValue = "Deny"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Network/virtualNetworks"
        },
        {
          "field"     = "Microsoft.Network/virtualNetworks/encryption.enabled",
          "notEquals" = "true"
        }
      ]
    },
    "then" = {
      "effect" = "[parameters('effect')]"
    }
  })
}
#prod-Ensure `User consent for applications` is set to `Do not allow user consent
resource "azurerm_policy_definition" "deny_user_consent_for_applications" {
  name                = "Deny-User-Consent-For-Applications"
  display_name        = "Ensure `User consent for applications` is set to `Do not allow user consent`"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensures that user consent for applications is set to 'Do not allow user consent'."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Authorization/policyAssignments"
        },
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "/providers/Microsoft.Authorization/policyDefinitions/userConsent"
        },
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "Allow"
        }
      ]
    },
    then = {
      effect = "Deny"
    }
  })
}
#prod-Ensure 'Cross Region Restore' is set to 'Enabled' on Recovery Services vaults
resource "azurerm_policy_definition" "cross_region_restore_enabled" {
  name                = "Cross-Region-Restore-Enabled"
  display_name        = "Ensure 'Cross Region Restore' is set to 'Enabled' on Recovery Services vaults"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure 'Cross Region Restore' is set to 'Enabled' on Recovery Services vaults"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Backup"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Deny"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.RecoveryServices/vaults"
        },
        {
          field     = "Microsoft.RecoveryServices/vaults/redundancySettings.crossRegionRestore",
          notEquals = "Enabled"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#prod-Ensure Guest users access restrictions is set to 'Guest user access is restricted to own directory
resource "azurerm_policy_definition" "deny_guest_user_access" {
  name                = "Deny-Guest-User-Access"
  display_name        = "Ensure That Guest users access restrictions is set to 'Guest user access is restricted to their own directory objects'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensures that guest user access is restricted to their own directory objects."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "Microsoft.Authorization/roleAssignments/principalType",
          equals = "Guest"
        },
        {
          field    = "Microsoft.Authorization/roleAssignments/roleDefinitionId",
          notEquals = "/providers/Microsoft.Authorization/roleDefinitions/{roleDefinitionId}"
        }
      ]
    },
    then = {
      effect = "deny"
    }
  })
}
#prod-Ensure MFA is Required for Windows Azure Service Management API
resource "azurerm_policy_definition" "require_mfa_for_azure_management_api" {
  name                = "Require-MFA-For-Azure-Management-API"
  display_name        = "Ensure Multi-factor Authentication is Required for Windows Azure Service Management API"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy ensures that MFA is required for accessing the Azure Management API."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      field  = "type",
      equals = "Microsoft.Management/managementGroups"
    },
    then = {
      effect = "deny"
    }
  })
}
#prod-Ensure Private Virtual Networks are used for Container Instances
resource "azurerm_policy_definition" "private_vnet_for_container_instances" {
  name                = "Private-VNet-For-Container-Instances"
  display_name        = "Ensure Private Virtual Networks are used for Container Instances"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy ensures that all container services like ACI or AKS are integrated with a private virtual network to enhance security and network isolation."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "Network"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      anyOf = [
        {
          allOf = [
            {
              field  = "type",
              equals = "Microsoft.ContainerInstance/containerGroups"
            },
            {
              field     = "Microsoft.ContainerInstance/containerGroups/sku",
              notEquals = "VirtualNetwork"
            }
          ]
        },
        {
          allOf = [
            {
              field  = "type",
              equals = "Microsoft.ContainerService/managedClusters"
            },
            {
              field     = "Microsoft.ContainerService/managedClusters/networkProfile.networkPlugin",
              notEquals = "azure"
            }
          ]
        }
      ]
    },
    then = {
      effect = "deny"
    }
  })
}
#prod-Ensure Public Network Access is Disabled-Storage Account
resource "azurerm_policy_definition" "public_network_access_disabled" {
  name                = "Public-Network-Access-Disabled"
  display_name        = "Ensure Public Network Access is Disabled"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Deny storage accounts if public network access is not disabled."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]
 
  metadata = jsonencode({
    version  = "1.0.0",
    category = "Security"
  })
 
  parameters = jsonencode({})
 
  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field  = "Microsoft.Storage/storageAccounts/publicNetworkAccess",
          notEquals = "Disabled"
        }
      ]
    }
    then = {
      effect = "deny"
    }
  })  
}
#prod-Ensure public network access on Recovery Services vaults is Disabled
resource "azurerm_policy_definition" "deny_public_network_access_recovery_vaults" {
  name                = "Deny-Public-Network-Access-Recovery-Vaults"
  display_name        = "Ensure public network access on Recovery Services vaults is Disabled"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure public network access on Recovery Services vaults is Disabled"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Backup"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Deny"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.RecoveryServices/vaults"
        },
        {
          field  = "Microsoft.RecoveryServices/vaults/publicNetworkAccess",
          equals = "Enabled"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#prod-Ensure 'SMB protocol version' is set to 'SMB 3.1.1' or higher for SMB file shares
resource "azurerm_policy_definition" "smb_protocol_version_required" {
  name                = "SMB-Protocol-Version-Required"
  display_name        = "Ensure 'SMB protocol version' is set to 'SMB 3.1.1' or higher for SMB file shares"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure 'SMB protocol version' is set to 'SMB 3.1.1' or higher for SMB file shares"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Storage"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Deny"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field  = "Microsoft.Storage/storageAccounts/sku.name",
          equals = "Standard_LRS"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#prod-Ensure soft delete for Azure File Shares is Enabled
resource "azurerm_policy_definition" "soft_delete_azure_file_shares" {
  name                = "Soft-Delete-Azure-File-Shares"
  display_name        = "Ensure soft delete for Azure File Shares is Enabled"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure soft delete for Azure File Shares is Enabled"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Storage"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Deny"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Storage/storageAccounts/fileServices/shares"
        },
        {
          field  = "Microsoft.Storage/storageAccounts/fileServices/shares/deleted",
          equals = "true"
        },
        {
          field  = "Microsoft.Storage/storageAccounts/fileServices/shares/remainingRetentionDays",
          exists = "true"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#prod-Ensure That ‘Users Can Register Applications’ Is Set to ‘No’
resource "azurerm_policy_definition" "deny_users_can_register_applications" {
  name                = "Deny-Users-Can-Register-Applications"
  display_name        = "Ensure That ‘Users Can Register Applications’ Is Set to ‘No’"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensures that 'Users Can Register Applications' is set to 'No'."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      field  = "Microsoft.Authorization/policyDefinitions/parameters",
      equals = "UsersCanRegisterApplications"
    },
    then = {
      effect = "deny"
    }
  })
}
#prod-Ensure that A Multi factor Authentication Policy Exists for All Users
resource "azurerm_policy_definition" "mfa_policy_for_all_users" {
  name                = "MFA-Policy-For-All-Users"
  display_name        = "Ensure that A Multi-factor Authentication Policy Exists for All Users"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that a Multi-factor Authentication Policy exists for all users."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Authorization/policyAssignments"
        },
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "/providers/Microsoft.Authorization/policyDefinitions/mfa"
        }
      ]
    },
    then = {
      effect = "Deny"
    }
  })
}
#prod-Ensure that 'Allow users to remember MFA on devices they trust' is Disabled
resource "azurerm_policy_definition" "deny_remember_mfa_on_trusted_devices" {
  name                = "Deny-Remember-MFA-On-Trusted-Devices"
  display_name        = "Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is Disabled"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy ensures that the option to allow users to remember multi-factor authentication on devices they trust is disabled."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      field  = "type",
      equals = "Microsoft.AzureActiveDirectory/b2cPolicies"
    },
    then = {
      effect = "deny"
    }
  })
}
#prod-Ensure that 'Minimum TLS version' is set to TLS v1.2
resource "azurerm_policy_definition" "minimum_tls_version_redis" {
  name                = "Minimum-TLS-Version-Redis"
  display_name        = "Ensure that 'Minimum TLS version' is set to TLS v1.2 (or higher)-Redis"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that 'Minimum TLS version' is set to TLS v1.2 (or higher)"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Deny"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Cache/Redis"
        },
        {
          field  = "Microsoft.Cache/Redis/sslPort",
          exists = "true"
        },
        {
          field     = "Microsoft.Cache/Redis/minimumTlsVersion",
          notEquals = "1.2"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#prod-Ensure that 'Owners can manage group membership requests in My Groups' is set to 'No'
resource "azurerm_policy_definition" "deny_owners_manage_group_membership_requests" {
  name                = "Deny-Owners-Manage-Group-Membership-Requests"
  display_name        = "Ensure that 'Owners can manage group membership requests in My Groups' is set to 'No'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy ensures that 'Owners can manage group membership requests in My Groups' is set to 'No'."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "/providers/Microsoft.Authorization/policyDefinitions/ownersCanManageGroupMembershipRequests"
        },
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "No"
        }
      ]
    },
    then = {
      effect = "deny"
    }
  })
}
#prod-Ensure that 'Public Network Access' is 'Disabled'-Redis
resource "azurerm_policy_definition" "public_network_access_disabled_redis" {
  name                = "Public-Network-Access-Disabled-Redis"
  display_name        = "Ensure that 'Public Network Access' is 'Disabled'-Redis"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that 'Public Network Access' is 'Disabled'"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Security"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Deny"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Cache/Redis"
        },
        {
          field  = "Microsoft.Cache/Redis/enableNonSslPort",
          exists = "true"
        },
        {
          field  = "Microsoft.Cache/Redis/enableNonSslPort",
          equals = "true"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#prod-Ensure that 'Restrict non admin users from creating tenants' is set to 'Yes'
resource "azurerm_policy_definition" "restrict_non_admin_tenant_creation" {
  name                = "Restrict-Non-Admin-Tenant-Creation"
  display_name        = "Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that only admin users can create tenants."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      field     = "Microsoft.Authorization/roleAssignments/roleDefinitionId",
      notEquals = "/providers/Microsoft.Authorization/roleDefinitions/{roleIdForTenantCreator}"
    },
    then = {
      effect = "deny"
    }
  })
}
#prod-Ensure that SKU BasicConsumption is not used on artifacts that need to be monitored
resource "azurerm_policy_definition" "deny_basic_consumption_sku" {
  name                = "Deny-Basic-Consumption-SKU"
  display_name        = "Ensure that SKU Basic Consumption is not used on artifacts that need to be monitored"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "Prevents deployment of resources using 'Basic' or 'Consumption' SKUs to ensure high availability and monitoring capabilities."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "General"
  })

  parameters = jsonencode({
    disallowedSkus = {
      type = "Array",
      metadata = {
        description = "List of disallowed SKUs.",
        displayName = "Disallowed SKUs"
      },
      defaultValue = [
        "Basic",
        "Consumption"
      ]
    }
  })

  policy_rule = jsonencode({
    if = {
      anyOf = [
        {
          allOf = [
            {
              field  = "type",
              equals = "Microsoft.Web/serverfarms"
            },
            {
              field = "Microsoft.Web/serverfarms/sku.name",
              in    = "[parameters('disallowedSkus')]"
            }
          ]
        },
        {
          allOf = [
            {
              field  = "type",
              equals = "Microsoft.ApiManagement/service"
            },
            {
              field = "Microsoft.ApiManagement/service/sku.name",
              in    = "[parameters('disallowedSkus')]"
            }
          ]
        },
        {
          allOf = [
            {
              field  = "type",
              equals = "Microsoft.Logic/workflows"
            },
            {
              field  = "Microsoft.Logic/workflows/integrationServiceEnvironment.id",
              exists = "false"
            }
          ]
        }
      ]
    },
    then = {
      effect = "deny"
    }
  })
}
#prod-Ensure that soft delete for blobs on Azure Blob Storage storage accounts is Enabled
resource "azurerm_policy_definition" "soft_delete_blobs_enabled" {
  name                = "Soft-Delete-Blobs-Enabled"
  display_name        = "Ensure that soft delete for blobs on Azure Blob Storage storage accounts is Enabled"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that soft delete for blobs on Azure Blob Storage storage accounts is Enabled"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Storage"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Deny"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Storage/storageAccounts/blobServices"
        },
        {
          field  = "Microsoft.Storage/storageAccounts/blobServices/deleteRetentionPolicy",
          exists = "false"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#prod-Ensure That 'Subscription leaving and entering Entra tenant' Is Set To 'Permit no one'
resource "azurerm_policy_definition" "restrict_subscription_movement" {
  name                = "restrict_Subscription_Movement"
  display_name        = "Ensure That 'Subscription leaving & entering Entra tenant' Is Set To 'Permit no one'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that subscription movement in and out of the Microsoft Entra tenant is restricted."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Subscription Management"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Authorization/policyAssignments"
        },
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "/providers/Microsoft.Authorization/policyDefinitions/allowSubscriptionMovement"
        },
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "enbaled"
        }
      ]
    },
    then = {
      effect = "deny"
    }
  })
}
#prod-Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No'
resource "azurerm_policy_definition" "deny_users_create_m365_groups" {
  name                = "Deny-Users-Create-M365-Groups"
  display_name        = "Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No'"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure that users cannot create Microsoft 365 groups in Azure portals, API, or PowerShell."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Identity"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "/providers/Microsoft.Authorization/policyDefinitions/creation"
        },
        {
          field  = "Microsoft.Authorization/policyAssignments/policyDefinitionId",
          equals = "true"
        }
      ]
    },
    then = {
      effect = "deny"
    }
  })
}
#prod-Ensure the web app has 'Client Certificates (Incoming client certificates)' set to 'On'
resource "azurerm_policy_definition" "webapp_client_cert_required" {
  name                = "WebApp-Client-Cert-Required"
  display_name        = "Ensure the web app has 'Client Certificates (Incoming client certificates)' set to 'On'"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "This policy ensures that Web Apps require incoming client certificates for mutual TLS authentication."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    version  = "1.0.0",
    category = "App Service"
  })

  parameters = jsonencode({})

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Web/sites"
        },
        {
          field     = "Microsoft.Web/sites/clientCertEnabled",
          notEquals = true
        }
      ]
    },
    then = {
      effect = "deny"
    }
  })
}
#prod-Ensure 'Versioning' is set to 'Enabled' on Azure Blob Storage storage accounts
resource "azurerm_policy_definition" "blob_versioning_enabled" {
  name                = "Blob-Versioning-Enabled"
  display_name        = "Ensure 'Versioning' is set to 'Enabled' on Azure Blob Storage storage accounts"
  policy_type         = "Custom"
  mode                = "All"
  description         = "Ensure 'Versioning' is set to 'Enabled' on Azure Blob Storage storage accounts"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    category = "Storage"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect of the policy."
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Deny"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type",
          equals = "Microsoft.Storage/storageAccounts/blobServices"
        },
        {
          field  = "Microsoft.Storage/storageAccounts/blobServices/isVersioningEnabled",
          equals = "false"
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#prod-Storage Accounts with custom domains assigned should be denied
resource "azurerm_policy_definition" "deny_storageaccount_customdomain" {
  name                = "Deny-StorageAccount-CustomDomain"
  display_name        = "Storage Accounts with custom domains assigned should be denied"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy denies the creation of Storage Accounts with custom domains assigned as communication cannot be encrypted, and always uses HTTP."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "Storage",
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "1.0.0",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:21:12.7438781Z",
    updatedBy  = null,
    updatedOn  = null
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect determines what happens when the policy rule is evaluated to match",
        displayName = "Effect"
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Deny"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          equals = "Microsoft.Storage/storageAccounts",
          field  = "type"
        },
        {
          anyOf = [
            {
              exists = "true",
              field  = "Microsoft.Storage/storageAccounts/customDomain"
            },
            {
              equals = "true",
              field  = "Microsoft.Storage/storageAccounts/customDomain.useSubDomainName"
            }
          ]
        }
      ]
    },
    then = {
          effect = "[parameters('effect')]"
        }
      })
    }
#prod-Storage Accounts with SFTP enabled should be denied
resource "azurerm_policy_definition" "deny_storage_sftp" {
  name                = "Deny-Storage-SFTP"
  display_name        = "Storage Accounts with SFTP enabled should be denied"
  policy_type         = "Custom"
  mode                = "Indexed"
  description         = "This policy denies the creation of Storage Accounts with SFTP enabled for Blob Storage."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category  = "Storage",
    source    = "https://github.com/Azure/Enterprise-Scale/",
    version   = "1.0.0"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect determines what happens when the policy rule is evaluated to match",
        displayName = "Effect"
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Deny"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "allOf" = [
        {
          "field"  = "type",
          "equals" = "Microsoft.Storage/storageAccounts"
        },
        {
          "field"  = "Microsoft.Storage/storageAccounts/isSftpEnabled",
          "equals" = "true"
        }
      ]
    },
    "then" = {
      "effect" = "[parameters('effect')]"
    }
  })
}
#prod-Subnets should have a Network Security Group
resource "azurerm_policy_definition" "deny_subnet_without_nsg" {
  name                = "Deny-Subnet-Without-Nsg"
  display_name        = "Subnets should have a Network Security Group (Manual)"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy denies the creation of a subnet without a Network Security Group. NSG help to protect traffic across subnet-level."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "Network",
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "2.0.0",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:21:07.3557624Z",
    updatedBy  = null,
    updatedOn  = null
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy",
        displayName = "Effect"
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Deny"
    },
    excludedSubnets = {
      type = "Array",
      metadata = {
        description = "Array of subnet names that are excluded from this policy",
        displayName = "Excluded Subnets"
      },
      defaultValue = [
        "GatewaySubnet",
        "AzureFirewallSubnet",
        "AzureFirewallManagementSubnet"
      ]
    }
  })

  policy_rule = jsonencode({
    if = {
      anyOf = [
        {
          allOf = [
            {
              equals = "Microsoft.Network/virtualNetworks",
              field  = "type"
            },
            {
              count = {
                field = "Microsoft.Network/virtualNetworks/subnets[*]",
                where = {
                  allOf = [
                    {
                      exists = "false",
                      field  = "Microsoft.Network/virtualNetworks/subnets[*].networkSecurityGroup.id"
                    },
                    {
                      field = "Microsoft.Network/virtualNetworks/subnets[*].name",
                      notIn = "[parameters('excludedSubnets')]"
                    }
                  ]
                }
              },
              notEquals = 0
            }
          ]
        },
        {
          allOf = [
            {
              equals = "Microsoft.Network/virtualNetworks/subnets",
              field  = "type"
            },
            {
              field = "name",
              notIn = "[parameters('excludedSubnets')]"
            },
            {
              exists = "false",
              field  = "Microsoft.Network/virtualNetworks/subnets/networkSecurityGroup.id"
            }
          ]
        }
      ]
    },
    then = {
      effect = "[parameters('effect')]"
    }
  })
}
#prod-Subnets should have a User Defined Route
resource "azurerm_policy_definition" "deny_subnet_without_udr" {
  name                = "Deny-Subnet-Without-Udr"
  display_name        = "Subnets should have a User Defined Route"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy denies the creation of a subnet without a User Defined Route (UDR)."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category   = "Network",
    source     = "https://github.com/Azure/Enterprise-Scale/",
    version    = "2.0.0",
    createdBy  = "54952db3-f0e2-4198-9d11-9deb0514f4c8",
    createdOn  = "2025-06-06T12:20:59.2405589Z",
    updatedBy  = null,
    updatedOn  = null
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "Enable or disable the execution of the policy",
        displayName = "Effect"
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Deny"
    },
    excludedSubnets = {
      type = "Array",
      metadata = {
        description = "Array of subnet names that are excluded from this policy",
        displayName = "Excluded Subnets"
      },
      defaultValue = [
        "AzureBastionSubnet"
      ]
    }
  })

  policy_rule = jsonencode({
    if = {
      anyOf = [
        {
          allOf = [
            {
              equals = "Microsoft.Network/virtualNetworks",
              field  = "type"
            },
            {
              count = {
                field = "Microsoft.Network/virtualNetworks/subnets[*]",
                where = {
                  allOf = [
                    {
                      exists = "false",
                      field  = "Microsoft.Network/virtualNetworks/subnets[*].routeTable.id"
                    },
                    {
                      field = "Microsoft.Network/virtualNetworks/subnets[*].name",
                      notIn = "[parameters('excludedSubnets')]"
                    }
                  ]
                }
              },
              notEquals = 0
            }
          ]
        },
        {
          allOf = [
            {
              equals = "Microsoft.Network/virtualNetworks/subnets",
              field  = "type"
            },
            {
              field = "name",
              notIn = "[parameters('excludedSubnets')]"
            },
            {
              exists = "false",
              field  = "Microsoft.Network/virtualNetworks/subnets/routeTable.id"
            }
          ]
        }
      ]
    },
      then = {
        effect = "[parameters('effect')]"
      }
    })
  }
#prod-User Defined Routes with 'Next Hop Type' set to 'Internet' or 'VirtualNet
resource "azurerm_policy_definition" "deny_udr_with_specific_nexthop" {
  name                = "Deny-UDR-With-Specific-NextHop"
  display_name        = "User Defined Routes with 'Next Hop Type' set to 'Internet' or 'VirtualNetworkGateway' should be denied"
  policy_type         = "Custom"
  mode                = "All"
  description         = "This policy denies the creation of a User Defined Route with 'Next Hop Type' set to 'Internet' or 'VirtualNetworkGateway'."
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  metadata = jsonencode({
    alzCloudEnvironments = [
      "AzureCloud",
      "AzureChinaCloud",
      "AzureUSGovernment"
    ],
    category  = "Network",
    source    = "https://github.com/Azure/Enterprise-Scale/",
    version   = "1.0.0"
  })

  parameters = jsonencode({
    effect = {
      type = "String",
      metadata = {
        description = "The effect determines what happens when the policy rule is evaluated to match",
        displayName = "Effect"
      },
      allowedValues = [
        "Audit",
        "Deny",
        "Disabled"
      ],
      defaultValue = "Deny"
    },
    excludedDestinations = {
      type = "Array",
      metadata = {
        description = "Array of route destinations that are to be denied",
        displayName = "Excluded Destinations"
      },
      defaultValue = [
        "Internet",
        "VirtualNetworkGateway"
      ]
    }
  })

  policy_rule = jsonencode({
    "if" = {
      "anyOf" = [
        {
          "allOf" = [
            {
              "equals" = "Microsoft.Network/routeTables",
              "field"  = "type"
            },
            {
              "count" = {
                "field" = "Microsoft.Network/routeTables/routes[*]",
                "where" = {
                  "field" = "Microsoft.Network/routeTables/routes[*].nextHopType",
                  "in"    = "[parameters('excludedDestinations')]"
                }
              },
              "notEquals" = 0
            }
          ]
        },
        {
          "allOf" = [
            {
              "equals" = "Microsoft.Network/routeTables/routes",
              "field"  = "type"
            },
            {
              "field" = "Microsoft.Network/routeTables/routes/nextHopType",
              "in"    = "[parameters('excludedDestinations')]"
            }
          ]
        }
      ]
    },
    "then" = {
      "effect" = "[parameters('effect')]"
    }
  })
}
#Initiative ims-builtin-corp-initiative-231
# Create ims-builtin-corp-initiative-231 with built-in definitions, assigned to IMS_Root MG
locals {
  ims_builtin_corp_policy_ids = [
{ id="b03bb370-5249-4ea4-9fce-2552e87e45fa", name="Disks and OS image should support TrustedLaunch"},
{ id="c95b54ad-0614-4633-ab29-104b01235cbf", name="Virtual Machine should have TrustedLaunch enabled"},
{ id="b0e86710-7fb7-4a6c-a064-32e9b829509e", name="Deploy - Configure private DNS zones for private endpoints connect to Azure SignalR Service"},
{ id="59efceea-0c96-497e-a4a1-4eb2290dac15", name="Configure periodic checking for missing system updates on azure virtual machines"},
{ id="bfea026e-043f-4ff4-9d1b-bf301ca7ff46", name="Configure periodic checking for missing system updates on azure Arc-enabled servers"},
{ id="6fac406b-40ca-413b-bf8e-0bf964659c25", name="Storage accounts should use customer-managed key for encryption"},
{ id="83cef61d-dbd1-4b20-a4fc-5fbc7da10833", name="MySQL servers should use customer-managed keys to encrypt data at rest"},
{ id="18adea5e-f416-4d0f-8aa8-d24321e3e274", name="PostgreSQL servers should use customer-managed keys to encrypt data at rest"},
{ id="051cba44-2429-45b9-9649-46cec11c7119", name="Azure API for FHIR should use a customer-managed key to encrypt data at rest"},
{ id="76a56461-9dc0-40f0-82f5-2453283afa2f", name="Azure AI Search services should use customer-managed keys to encrypt data at rest"},
{ id="a1ad735a-e96f-45d2-a7b2-9a4932cab7ec", name="Event Hub namespaces should use a customer-managed key for encryption"},
{ id="295fc8b1-dc9f-4f53-9c61-3f313ceab40a", name="Service Bus Premium namespaces should use a customer-managed key for encryption"},
{ id="f9d614c5-c173-4d56-95a7-b4437057d193", name="Function apps should use the latest TLS version"},
{ id="f0e6e85b-9b9f-4a4b-b67b-f730d42f1b0b", name="App Service apps should use the latest TLS version"},
{ id="1f01f1c7-539c-49b5-9ef4-d4ffa37d22e0", name="Configure Function apps to use the latest TLS version"},
{ id="fa3a6357-c6d6-4120-8429-855577ec0063", name="Configure Function app slots to use the latest TLS version"},
{ id="ae44c1d1-0df2-4ca9-98fa-a3d3ae5b409d", name="Configure App Service apps to use the latest TLS version"},
{ id="014664e7-e348-41a3-aeb9-566e4ff6a9df", name="Configure App Service app slots to use the latest TLS version"},
{ id="a8793640-60f7-487c-b5c3-1d37215905c4", name="SQL Managed Instance should have the minimal TLS version of 1.2"},
{ id="44433aa3-7ec2-4002-93ea-65c65ff0310a", name="Configure Azure Defender for open-source relational databases to be enabled"},
{ id="8e86a5b6-b9bd-49d1-8e21-4bb8a0862222", name="Configure Azure Defender for servers to be enabled"},
{ id="13ce0167-8ca6-4048-8e6b-f996402e3c1b", name="Configure machines to receive a vulnerability assessment provider"},
{ id="50ea7265-7d8c-429e-9a7d-ca1f410191c3", name="Configure Azure Defender for SQL servers on machines to be enabled"},
{ id="b40e7bcd-a1e5-47fe-b9cf-2f534d0bfb7d", name="Configure Azure Defender for App Service to be enabled"},
{ id="cfdc5972-75b3-4418-8ae1-7f5c36839390", name="Configure Microsoft Defender for Storage to be enabled"},
{ id="c9ddb292-b203-4738-aead-18e2716e858f", name="Configure Microsoft Defender for Containers to be enabled"},
{ id="64def556-fbad-4622-930e-72d1d5589bf5", name="Configure Azure Kubernetes Service clusters to enable Defender profile"},
{ id="a8eff44f-8c92-45c3-a3fb-9880802d67a7", name="Deploy Azure Policy Add-on to Azure Kubernetes Service clusters"},
{ id="1f725891-01c0-420a-9059-4fa46cb770b7", name="Configure Microsoft Defender for Key Vault plan"},
{ id="b7021b2b-08fd-4dc0-9de7-3c6ece09faf9", name="Configure Azure Defender for Resource Manager to be enabled"},
{ id="b99b73e7-074b-4089-9395-b7236f094491", name="Configure Azure Defender for Azure SQL database to be enabled"},
{ id="82bf5b87-728b-4a74-ba4d-6123845cf542", name="Configure Microsoft Defender for Azure Cosmos DB to be enabled"},
{ id="72f8cee7-2937-403d-84a1-a4e3e57f3c21", name="Configure Microsoft Defender CSPM plan"},
{ id="766e621d-ba95-4e43-a6f2-e945db3d7888", name="Setup subscriptions to transition to an alternative vulnerability assessment solution"},
{ id="86a912f6-9a06-4e26-b447-11b16ba8659f", name="Deploy SQL DB transparent data encryption"},
{ id="84d327c3-164a-4685-b453-900478614456", name="Configure Azure Key Vault Managed HSM to disable public network access"},
{ id="ac673a9a-f77d-4846-b2d8-a57f8e1c01dc", name="Configure key vaults to enable firewall"},
{ id="3cf2ab00-13f1-4d0c-8971-2ac904541a7e", name="Add system-assigned managed identity to enable Guest Configuration assignments on virtual machines with no identities"},
{ id="331e8ea8-378a-410f-a2e5-ae22f38bb0da", name="Deploy the Linux Guest Configuration extension to enable Guest Configuration assignments on Linux VMs"},
{ id="385f5831-96d4-41db-9a3c-cd3af78aaae6", name="Deploy the Windows Guest Configuration extension to enable Guest Configuration assignments on Windows VMs"},
{ id="72650e9f-97bc-4b2a-ab5f-9781a9fcecbc", name="Windows machines should meet requirements of the Azure compute security baseline"},
{ id="fc9b3da7-8347-4380-8e70-0a0361d8dedd", name="Linux machines should meet requirements for the Azure compute security baseline"},
{ id="2514263b-bc0d-4b06-ac3e-f262c0979018", name="Immutability must be enabled for backup vaults"},
{ id="d6f6f560-14b7-49a4-9fc8-d2c3a9807868", name="Immutability must be enabled for Recovery Services vaults"},
{ id="9798d31d-6028-4dee-8643-46102185c016", name="Soft delete should be enabled for Backup Vaults"},
{ id="31b8092a-36b8-434b-9af7-5ec844364148", name="Soft delete must be enabled for Recovery Services Vaults."},
{ id="c58e083e-7982-4e24-afdc-be14d312389e", name="Multi-User Authorization (MUA) must be enabled for Backup Vaults."},
{ id="c7031eab-0fc0-4cd9-acd0-4497bd66d91a", name="Multi-User Authorization (MUA) must be enabled for Recovery Services Vaults."},
{ id="7ca8c8ac-3a6e-493d-99ba-c5fa35347ff2", name="Configure API Management services to disable access to API Management public service configuration endpoints"},
{ id="a5e3fe8f-f6cd-4f1d-bbf6-c749754a724b", name="Configure App Service apps to turn off remote debugging"},
{ id="cca5adfe-626b-4cc6-8522-f5b6ed2391bd", name="Configure App Service app slots to turn off remote debugging"},
{ id="70adbb40-e092-42d5-a6f8-71c540a5efdb", name="Configure Function app slots to turn off remote debugging"},
{ id="5e97b776-f380-4722-a9a3-e7f0be029e79", name="Configure App Service apps to disable local authentication for SCM sites"},
{ id="572e342c-c920-4ef5-be2e-1ed3c6a51dc5", name="Configure App Service apps to disable local authentication for FTP deployments"},
{ id="2c034a29-2a5f-4857-b120-f800fe5549ae", name="Configure App Service app slots to disable local authentication for SCM sites"},
{ id="25a5046c-c423-4805-9235-e844ae9ef49b", name="Configure Function apps to turn off remote debugging"},
{ id="08cf2974-d178-48a0-b26d-f6b8e555748b", name="Configure Function app slots to only be accessible over HTTPS"},
{ id="0f98368e-36bc-4716-8ac2-8f8067203b63", name="Configure App Service apps to only be accessible over HTTPS"},
{ id="242222f3-4985-4e99-b5ef-086d6a6cb01c", name="Configure Function app slots to disable public network access"},
{ id="2374605e-3e0b-492b-9046-229af202562c", name="Configure App Service apps to disable public network access"},
{ id="c6c3e00e-d414-4ca4-914f-406699bb8eee", name="Configure App Service app slots to disable public network access"},
{ id="dea83a72-443c-4292-83d5-54a2f98749c0", name="Automation Account should have Managed Identity"},
{ id="30d1d58e-8f96-47a5-8564-499a3f3cca81", name="Configure Azure Automation account to disable local authentication"},
{ id="23b36a7c-9d26-4288-a8fd-c1d2fa284d8c", name="Configure Azure Automation accounts to disable public network access"},
{ id="ad5621d6-a877-4407-aa93-a950b428315e", name="BotService resources should use private link"},
{ id="4eb216f2-9dba-4979-86e6-5d7e63ce3b75", name="Configure Azure AI Search services to disable local authentication"},
{ id="9cee519f-d9c1-4fd9-9f79-24ec3449ed30", name="Configure Azure AI Search services to disable public network access"},
{ id="47ba1dd7-28d9-4b07-a8d5-9813bed64e0c", name="Configure Cognitive Services accounts to disable public network access"},
{ id="14de9e63-1b31-492e-a5a3-c3f7fd57f555", name="Configure Cognitive Services accounts to disable local authentication methods"},
{ id="b4330a05-a843-4bc8-bf9a-cacce50c67f4", name="Resource logs in Search services should be enabled"},
{ id="79fdfe03-ffcb-4e55-b4d0-b925b8241759", name="Configure container registries to disable local admin account."},
{ id="a9b426fe-8856-4945-8600-18c5dd1cca2a", name="Configure container registries to disable repository scoped access token."},
{ id="785596ed-054f-41bc-aaec-7f3d0ba05725", name="Configure container registries to disable ARM audience token authentication."},
{ id="cced2946-b08a-44fe-9fd9-e4ed8a779897", name="Configure container registries to disable anonymous authentication."},
{ id="a3701552-92ea-433e-9d17-33b7f1208fc9", name="Configure Container registries to disable public network access"},
{ id="dc2d41d1-4ab1-4666-a3e1-3d51c43e0049", name="Configure Cosmos DB database accounts to disable local authentication"},
{ id="b5f04e03-92a3-4b09-9410-2cc5e5047656", name="Deploy Advanced Threat Protection for Cosmos DB Accounts"},
{ id="4750c32b-89c0-46af-bfcb-2e4541a818d5", name="Azure Cosmos DB key based metadata write access should be disabled"},
{ id="da69ba51-aaf1-41e5-8651-607cd0b37088", name="Configure CosmosDB accounts to disable public network access"},
{ id="7b32f193-cb28-4e15-9a98-b9556db0bafa", name="Configure Azure Data Explorer to disable public network access"},
{ id="08b1442b-7789-4130-8506-4f99a97226a7", name="Configure Data Factories to disable public network access"},
{ id="2dd0e8b9-4289-4bb0-b813-1883298e9924", name="Configure Azure Event Grid partner namespaces to disable local authentication"},
{ id="8ac2748f-3bf1-4c02-a3b6-92ae68cf75b1", name="Configure Azure Event Grid domains to disable local authentication"},
{ id="1c8144d9-746a-4501-b08c-093c8d29ad04", name="Configure Azure Event Grid topics to disable local authentication"},
{ id="898e9824-104c-4965-8e0e-5197588fa5d4", name="Modify - Configure Azure Event Grid domains to disable public network access"},
{ id="36ea4b4b-0f7f-4a54-89fa-ab18f555a172", name="Modify - Configure Azure Event Grid topics to disable public network access"},
{ id="57f35901-8389-40bb-ac49-3ba4f86d889d", name="Configure Azure Event Hub namespaces to disable local authentication"},
{ id="1b708b0a-3380-40e9-8b79-821f9fa224cc", name="Disable Command Invoke on Azure Kubernetes Service clusters"},
{ id="dbbdc317-9734-4dd8-9074-993b29c69008", name="Azure Kubernetes Clusters should enable Key Management Service (KMS)"},
{ id="46238e2f-3f6f-4589-9f3f-77bed4116e67", name="Azure Kubernetes Clusters should use Azure CNI"},
{ id="f110a506-2dcb-422e-bcea-d533fc8c35e2", name="Azure Machine Learning compute instances should be recreated to get the latest software updates"},
{ id="a6f9a2d0-cff7-4855-83ad-4cd750666512", name="Configure Azure Machine Learning Computes to disable local authentication methods"},
{ id="a10ee784-7409-4941-b091-663697637c0f", name="Configure Azure Machine Learning Workspaces to disable public network access"},
{ id="7804b5c7-01dc-4723-969b-ae300cc07ff1", name="Azure Machine Learning Computes should be in a virtual network"},
{ id="45e05259-1eb5-4f70-9574-baf73e9d219b", name="Azure Machine Learning workspaces should use private link"},
{ id="afe0c3be-ba3b-4544-ba52-0c99672a8ad6", name="Resource logs in Azure Machine Learning Workspaces should be enabled"},
{ id="53c70b02-63dd-11ea-bc55-0242ac130003", name="Configure allowed module authors for specified Azure Machine Learning computes"},
{ id="77eeea86-7e81-4a7d-9067-de844d096752", name="Configure allowed Python packages for specified Azure Machine Learning computes"},
{ id="5853517a-63de-11ea-bc55-0242ac130003", name="Configure allowed registries for specified Azure Machine Learning computes"},
{ id="80ed5239-4122-41ed-b54a-6f1fa7552816", name="Configure Advanced Threat Protection to be enabled on Azure database for MySQL servers"},
{ id="d6759c02-b87f-42b7-892e-71b3f471d782", name="Azure AI Services resources should use Azure Private Link"},
{ id="d45520cb-31ca-44ba-8da2-fcf914608544", name="Configure Azure AI Services resources to disable local key access (disable local authentication)"},
{ id="1b4d1c4e-934c-4703-944c-27c82c06bebb", name="Diagnostic logs in Azure AI services resources should be enabled"},
{ id="db048e65-913c-49f9-bb5f-1084184671d3", name="Configure Advanced Threat Protection to be enabled on Azure database for PostgreSQL servers"},
{ id="910711a6-8aa2-4f15-ae62-1e5b2ed3ef9e", name="Configure Azure Service Bus namespaces to disable local authentication"},
{ id="c5a62eb0-c65a-4220-8a4d-f70dd4ca95dd", name="Configure Azure Defender to be enabled on SQL managed instances"},
{ id="6134c3db-786f-471e-87bc-8f479dc890f6", name="Deploy Advanced Data Security on SQL servers"},
{ id="28b0b1e5-17ba-4963-a7a4-5a1ab4400a0b", name="Configure Azure SQL Server to disable public network access"},
{ id="0e07b2e9-6cd9-4c40-9ccb-52817b95133b", name="Modify - Configure Azure File Sync to disable public network access"},
{ id="13502221-8df0-4414-9937-de9c5c4e396b", name="Configure your Storage account public access to be disallowed"},
{ id="a06d0189-92e8-4dba-b0c4-08d7669fce7d", name="Configure storage accounts to disable public network access"},
{ id="951c1558-50a5-4ca3-abb6-a93e3e2367a6", name="Configure Microsoft Defender for SQL to be enabled on Synapse workspaces"},
{ id="c3624673-d2ff-48e0-b28c-5de1c6767c3c", name="Configure Synapse Workspaces to use only Microsoft Entra identities for authentication during workspace creation"},
{ id="56fd377d-098c-4f02-8406-81eb055902b8", name="IP firewall rules on Azure Synapse workspaces should be removed"},
{ id="8b5c654c-fb07-471b-aa8f-15fea733f140", name="Configure Azure Synapse Workspace Dedicated SQL minimum TLS version"},
{ id="5c8cad01-ef30-4891-b230-652dadb4876a", name="Configure Azure Synapse workspaces to disable public network access"},
{ id="ce6ebf1d-0b94-4df9-9257-d8cacc238b4f", name="Configure Azure Virtual Desktop workspaces to disable public network access"},
{ id="2a0913ff-51e7-47b8-97bb-ea17127f7c8d", name="Configure Azure Virtual Desktop hostpools to disable public network access"},
{ id="df73bd95-24da-4a4f-96b9-4e8b94b402bd", name="API Management should disable public network access to the service configuration endpoints"},
{ id="2e94d99a-8a36-4563-bc77-810d8893b671", name="Azure Recovery Services vaults should use customer-managed keys for encrypting backup data"},
{ id="7d7be79c-23ba-4033-84dd-45e2a5ccdd67", name="Both operating systems and data disks in Azure Kubernetes Service clusters should be encrypted by customer-managed keys"},
{ id="970f84d8-71b6-4091-9979-ace7e3fb6dbb", name="HPC Cache accounts should use customer-managed key for encryption"},
{ id="ca91455f-eace-4f96-be59-e6e2c35b4816", name="Managed disks should be double encrypted with both platform-managed and customer-managed keys"},
{ id="f0e5abd0-2554-4736-b7c0-4ffef23475ef", name="Queue Storage should use customer-managed key for encryption"},
{ id="ac01ad65-10e5-46df-bdd9-6b0cad13e1d2", name="SQL managed instances should use customer-managed keys to encrypt data at rest"},
{ id="0a370ff3-6cab-4e85-8995-295fd854c5b8", name="SQL servers should use customer-managed keys to encrypt data at rest"},
{ id="b5ec538c-daa0-4006-8596-35468b9148e8", name="Storage account encryption scopes should use customer-managed keys to encrypt data at rest"},
{ id="7c322315-e26d-4174-a99e-f49d351b4688", name="Table Storage should use customer-managed key for encryption"},
{ id="5b9159ae-1701-4a6f-9a7a-aa9c8ddd0580", name="Container registries should be encrypted with a customer-managed key"},
{ id="ba769a63-b8cc-4b2d-abf6-ac33c7204be8", name="Azure Machine Learning workspaces should be encrypted with a customer-managed key"},
{ id="67121cc7-ff39-4ab8-b7e3-95b84dab487d", name="Azure AI Services resources should encrypt data at rest with a customer-managed key (CMK)"},
{ id="1f905d99-2ab7-462c-a6b0-f709acca6c8f", name="Azure Cosmos DB accounts should use customer-managed keys to encrypt data at rest"},
{ id="86efb160-8de7-451d-bc08-5d475b0aadae", name="Azure Data Box jobs should use a customer-managed key to encrypt the device unlock password"},
{ id="87ba29ef-1ab3-4d82-b763-87fcd4f531f7", name="Azure Stream Analytics jobs should use customer-managed keys to encrypt data"},
{ id="f7d52b2d-e161-4dfa-a82b-55e564167385", name="Azure Synapse workspaces should use customer-managed keys to encrypt data at rest"},
{ id="99e9ccd8-3db9-4592-b0d1-14b1715a4d8a", name="Azure Batch account should use customer-managed keys to encrypt data"},
{ id="56a5ee18-2ae6-4810-86f7-18e39ce5629b", name="Azure Automation accounts should use customer-managed keys to encrypt data at rest"},
{ id="702dd420-7fcc-42c5-afe8-4026edd20fe0", name="OS and data disks should be encrypted with a customer-managed key"},
{ id="0aa61e00-0a01-4a3c-9945-e93cffedf0e6", name="Azure Container Instance container group should use customer-managed key for encryption"},
{ id="81e74cea-30fd-40d5-802f-d72103c2aaaa", name="Azure Data Explorer encryption at rest should use a customer-managed key"},
{ id="4ec52d6d-beb7-40c4-9a9e-fe753254690e", name="Azure data factories should be encrypted with a customer-managed key"},
{ id="51522a96-0869-4791-82f3-981000c2c67f", name="Bot Service should be encrypted with a customer-managed key"},
{ id="f466b2a6-823d-470d-8ea5-b031e72d79ae", name="App Service app slots that use PHP should use a specified 'PHP version'" },
{ id="9c014953-ef68-4a98-82af-fd0f6b2306c8", name="App Service app slots that use Python should use a specified 'Python version'" },
{ id="871b205b-57cf-4e1e-a234-492616998bf7", name="App Service apps should have local authentication methods disabled for FTP deployments" },
{ id="aede300b-d67f-480a-ae26-4b3dfb1a1fdc", name="App Service apps should have local authentication methods disabled for SCM site deployments" },
{ id="cb510bfd-1cba-4d9f-a230-cb0976f4bb71", name="App Service apps should have remote debugging turned off" },
{ id="91a78b24-f231-4a8a-8da9-02c35b2b6510", name="App Service apps should have resource logs enabled" },
{ id="4d24b6d4-5e53-4a4f-a7f4-618fa573ee4b", name="App Service apps should require FTPS only" },
{ id="8c122334-9d20-4eb8-89ea-ac9a705b74ae", name="App Service apps should use latest 'HTTP Version'" },
{ id="2b9ad585-36bc-4615-b300-fd4435808332", name="App Service apps should use managed identity" },
{ id="7261b898-8a84-4db8-9e04-18527132abb3", name="App Service apps that use PHP should use a specified 'PHP version'" },
{ id="7008174a-fd10-4ef0-817e-fc820a951d73", name="App Service apps that use Python should use a specified 'Python version'" },
{ id="e1d1b522-02b0-4d18-a04f-5ab62d20445f", name="Function app slots that use Java should use a specified 'Java version'" },
{ id="c75248c1-ea1d-4a9c-8fc9-29a6aabd5da8", name="Function apps should have authentication enabled" },
{ id="ab6a902f-9493-453b-928d-62c30b11b5a6", name="Function apps should have Client Certificates (Incoming client certificates) enabled" },
{ id="399b2637-a50f-4f95-96f8-3a145476eb15", name="Function apps should require FTPS only" },
{ id="e2c1c086-2d84-4019-bff3-c44ccd95113c", name="Function apps should use latest 'HTTP Version'" },
{ id="0da106f2-4ca3-48e8-bc85-c638fe6aea8f", name="Function apps should use managed identity" },
{ id="9d0b6ea4-93e2-4578-bf2f-6bb17d22b4bc", name="Function apps that use Java should use a specified 'Java version'" },
{ id="d6588149-9f06-462c-a076-56aece45b5ba", name="[Preview]: Azure Backup Vaults should use customer-managed keys for encrypting backup data. Also an option to enforce Infra Encryption." },
{ id="f19b0c83-716f-4b81-85e3-2dbf057c35d6", name="[Preview]: Disable Cross Subscription Restore for Azure Recovery Services vaults" },
{ id="4d479a11-f2b5-4f0a-bb1e-d2332aa95cda", name="[Preview]: Disable Cross Subscription Restore for Backup Vaults" },
{ id="428256e6-1fac-4f48-a757-df34c2b3336d", name="Resource logs in Batch accounts should be enabled" },
{ id="06a78e20-9358-41c9-923c-fb736d382a4d", name="Audit VMs that do not use managed disks" },
{ id="58440f8a-10c5-4151-bdce-dfbaad4a20b7", name="CosmosDB accounts should use private link" },
{ id="057ef27e-665e-4328-8ea3-04b3122bd9fb", name="Resource logs in Azure Data Lake Store should be enabled" },
{ id="c95c74d9-38fe-4f0d-af86-0c7d626a315c", name="Resource logs in Data Lake Analytics should be enabled" },
{ id="83a214f7-d01a-484b-91a9-ed54470c9a6a", name="Resource logs in Event Hub should be enabled" },
{ id="a451c1ef-c6ca-483d-87ed-f49761e3ffb5", name="Audit usage of custom RBAC roles" },
{ id="383856f8-de7f-44a2-81fc-e5135b5c2aa4", name="Resource logs in IoT Hub should be enabled" },
{ id="a6abeaec-4d90-4a02-805f-6b26c4d3fbe9", name="Azure Key Vaults should use private link" },
{ id="cf820ca0-f99e-4f3e-84fb-66e913812d21", name="Resource logs in Key Vault should be enabled" },
{ id="34f95f76-5386-4de7-b824-0d8478470c9d", name="Resource logs in Logic Apps should be enabled" },
{ id="fbb99e8e-e444-4da0-9ff1-75c92f5a85b2", name="Storage account containing the container with activity logs must be encrypted with BYOK" },
{ id="27960feb-a23c-4577-8d36-ef8b5f35e0be", name="All flow log resources should be in enabled state" },
{ id="4c3c6c5f-0d47-4402-99b8-aa543dd8bcee", name="Audit flow logs configuration for every virtual network" },
{ id="b6e2945c-0b7b-40f5-9233-7a5323b5cdc6", name="Network Watcher should be enabled" },
{ id="dacf07fa-0eea-4486-80bc-b93fae88ac40", name="Connection throttling should be enabled for PostgreSQL flexible servers" },
{ id="c29c38cb-74a7-4505-9a06-e588ab86620a", name="Enforce SSL connection should be enabled for PostgreSQL flexible servers" },
{ id="70be9e12-c935-49ac-9bd8-fd64b85c1f87", name="Log checkpoints should be enabled for PostgreSQL flexible servers" },
{ id="97566dd7-78ae-4997-8b36-1c7bfe0d8121", name="[Preview]: Secure Boot should be enabled on supported Windows virtual machines" },
{ id="1c30f9cd-b84c-49cc-aa2c-9288447cc3b3", name="[Preview]: vTPM should be enabled on supported virtual machines" },
{ id="2913021d-f2fd-4f3d-b958-22354e2bdbcb", name="Azure Defender for App Service should be enabled" },
{ id="7fe3b40f-802b-4cdd-8bd4-fd799c948cc2", name="Azure Defender for Azure SQL Database servers should be enabled" },
{ id="0e6763cc-5078-4e64-889d-ff4d9a839047", name="Azure Defender for Key Vault should be enabled" },
{ id="0a9fbe0d-c5c4-4da8-87d8-f4fd77338835", name="Azure Defender for open-source relational databases should be enabled" },
{ id="c3d20c29-b36d-48fe-808b-99a87530ad99", name="Azure Defender for Resource Manager should be enabled" },
{ id="4da35fc9-c9e7-4960-aec9-797fe7d9051d", name="Azure Defender for servers should be enabled" },
{ id="6581d072-105e-4418-827f-bd446d56421b", name="Azure Defender for SQL servers on machines should be enabled" },
{ id="6e2593d9-add6-4083-9c9b-4b7d2188c899", name="Email notification for high severity alerts should be enabled" },
{ id="339353f6-2387-4a45-abe4-7f529d121046", name="Guest accounts with owner permissions on Azure resources should be removed" },
{ id="e9ac8f8e-ce22-4355-8f04-99b911d6be52", name="Guest accounts with read permissions on Azure resources should be removed" },
{ id="94e1c2ac-cbbe-4cac-a2b5-389c812dee87", name="Guest accounts with write permissions on Azure resources should be removed" },
{ id="22730e10-96f6-4aac-ad84-9383d35b5917", name="Management ports should be closed on your virtual machines" },
{ id="adbe85b5-83e6-4350-ab58-bf3a4f736e5e", name="Microsoft Defender for Azure Cosmos DB should be enabled" },
{ id="1c988dd6-ade4-430f-a608-2a3e5b0a6d38", name="Microsoft Defender for Containers should be enabled" },
{ id="640d2586-54d2-465f-877f-9ffc1d2109f4", name="Microsoft Defender for Storage should be enabled" },
{ id="feedbf84-6b99-488c-acc2-71c829aa5ffc", name="SQL databases should have vulnerability findings resolved" },
{ id="4f4f78b8-e367-4b10-a341-d9a4ad5cf1c7", name="Subscriptions should have a contact email address for security issues" },
{ id="f8d36e2f-389b-4ee4-898d-21aeb69a0f45", name="Resource logs in Service Bus should be enabled" },
{ id="1f314764-cb73-4fc9-b863-8eca98ac36e9", name="An Azure Active Directory administrator should be provisioned for SQL servers" },
{ id="a6fb4358-5bf4-4ad7-ba82-2cd2f41ce5e9", name="Auditing on SQL server should be enabled" },
{ id="abfb4388-5bf4-4ad7-ba82-2cd2f41ceae9", name="Azure Defender for SQL should be enabled for unprotected Azure SQL servers" },
{ id="abfb7388-5bf4-4ad7-ba99-2cd2f41cebb9", name="Azure Defender for SQL should be enabled for unprotected SQL Managed Instances" },
{ id="5345bb39-67dc-4960-a1bf-427e16b9a0bd", name="Connection throttling should be enabled for PostgreSQL database servers" },
{ id="eb6f77b9-bd53-4e35-a23d-7f65d5f0e446", name="Disconnections should be logged for PostgreSQL database servers." },
{ id="e802a67a-daf5-4436-9ea6-f6d821dd0c5d", name="Enforce SSL connection should be enabled for MySQL database servers" },
{ id="d158790f-bfb0-486c-8631-2dc6b4e8e6af", name="Enforce SSL connection should be enabled for PostgreSQL database servers" },
{ id="eb6f77b9-bd53-4e35-a23d-7f65d5f0e43d", name="Log checkpoints should be enabled for PostgreSQL database servers" },
{ id="eb6f77b9-bd53-4e35-a23d-7f65d5f0e442", name="Log connections should be enabled for PostgreSQL database servers" },
{ id="eb6f77b9-bd53-4e35-a23d-7f65d5f0e8f3", name="Log duration should be enabled for PostgreSQL database servers" },
{ id="89099bee-89e0-4b26-a5f4-165451757743", name="SQL servers with auditing to storage account destination should be configured with 90 days retention or higher" },
{ id="17k78e20-9358-41c9-923c-fb736d382a12", name="Transparent Data Encryption on SQL databases should be enabled" },
{ id="1b7aa243-30e4-4c9e-bca8-d0d3022b634a", name="Vulnerability assessment should be enabled on SQL Managed Instance" },
{ id="ef2a8f2a-b3d9-49cd-a8a8-9a3aaaf647d9", name="Vulnerability assessment should be enabled on your SQL servers" },
{ id="bf045164-79ba-4215-8f95-f8048dc1780b", name="Geo-redundant storage should be enabled for Storage Accounts" },
{ id="6edd7eda-6dd8-40f7-810d-67160c639cd9", name="Storage accounts should use private link" },
{ id="f9be5368-9bf5-4b84-9e0a-7850da98bb46", name="Resource logs in Azure Stream Analytics should be enabled" },
{ id="3aa87b5a-7813-4b57-8a43-42dd9df5aaa7", name="Azure Active Directory Domain Services managed domains should use TLS 1.2 only mode"},
{ id="51c1490f-3319-459c-bbbc-7f391bbed753", name="Azure Databricks Clusters should disable public IP"},
{ id="9c25c9e4-ee12-4882-afd2-11fb9d87893f", name="Azure Databricks Workspaces should be in a virtual network"},
{ id="0e7849de-b939-4c50-ab48-fc6b0f5eeba2", name="Azure Databricks Workspaces should disable public network access"},
{ id="679da822-78a7-4eff-8fff-a899454a9970", name="Azure Front Door Standard and Premium should be running minimum TLS version of 1.2"},
{ id="6a92fe1f-0b86-44ae-843d-2db3d2b571ae", name="ElasticSan should disable public network access"},
{ id="67dcad1a-ec60-45df-8fd0-14c9d29eeaa2", name="Azure Event Grid namespaces should disable public network access"},
{ id="510ec8b2-cb9e-461d-b7f3-6b8678c31182", name="Public network access for Azure Device Update for IoT Hub accounts should be disabled"},
{ id="2d6830fb-07eb-48e7-8c4d-2a442b35f0fb", name="Public network access on Azure IoT Hub should be disabled"},
{ id="cd870362-211d-4cad-9ad9-11e5ea4ebbc1", name="Public network access should be disabled for IoT Central"},
{ id="7bca8353-aa3b-429b-904a-9229c4385837", name="Subnets should be private"},
{ id="c36a325b-ae04-4863-ad4f-19c6678f8e08", name="Configure your Storage account to enable blob versioning"}

  ]
}

resource "azurerm_policy_set_definition" "ims-builtin-corp-initiative-231" {
  name                = "ims-builtin-corp-initiative-231"
  display_name        = "ims-builtin-corp-initiative-231"
  policy_type         = "Custom"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  dynamic "policy_definition_reference" {
    for_each = local.ims_builtin_corp_policy_ids
    content {
      policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/${policy_definition_reference.value.id}"
      reference_id         = policy_definition_reference.value.name

    }
  }
}

#Initiative ims-builtin-prod-initiative-167-169
# Create ims-fsi-builtin-prod-deny-initiative with built-in definitions, assigned to IMS_Root MG
locals {
  ims_builtin_prod_policy_ids = [
{ id="98728c90-32c7-4049-8429-847dc0f4fe37", name="Key Vault secrets should have an expiration date"},
{ id="152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0", name="Key Vault keys should have an expiration date"},
{ id="55615ac9-af46-4a59-874e-391cc3dfb490", name="Azure Key Vault should have firewall enabled or public network access disabled"},
{ id="0a075868-4c26-42ef-914c-5bc007359560", name="Certificates should have the specified maximum validity period"},
{ id="8405fdab-1faf-48aa-b702-999c9c172094", name="Managed disks should disable public network access"},
{ id="1a5b4dca-0b6f-4cf5-907c-56316bc1bf3d", name="Kubernetes clusters should be accessible only over HTTPS"},
{ id="0e80e269-43a4-4ae9-b5bc-178126b8a5cb", name="Container Apps should only be accessible over HTTPS"},
{ id="a4af4a39-4135-47fb-b175-47fbdf85311d", name="App Service apps should only be accessible over HTTPS"},
{ id="d6545c6b-dd9d-4265-91e6-0b451e2f1c50", name="App Service Environment should have TLS 1.0 and 1.1 disabled"},
{ id="5e5dbe3f-2702-4ffc-8b1e-0cae008a5c71", name="Function app slots should only be accessible over HTTPS"},
{ id="6d555dd1-86f2-4f1c-8ed7-5abae7c6cbab", name="Function apps should only be accessible over HTTPS"},
{ id="ae1b9a8c-dfce-4605-bd91-69213b4a26fc", name="App Service app slots should only be accessible over HTTPS"},
{ id="32e6bbec-16b6-44c2-be37-c5b672d103cf", name="Azure SQL Database should be running TLS version 1.2 or newer"},
{ id="fe83a0eb-a853-422d-aac2-1bffd182c5d0", name="Storage accounts should have the specified minimum TLS version"},
{ id="cb3738a6-82a2-4a18-b87b-15217b9deff4", name="Azure Synapse Workspace SQL Server should be running TLS version 1.2 or newer"},
{ id="f1cc7827-022c-473e-836e-5a51cae0b249", name="API Management secret named values should be stored in Azure Key Vault"},
{ id="ef619a2c-cc4d-4d03-b2ba-8c94a834d85b", name="API Management services should use a virtual network"},
{ id="ee7495e7-3ba7-40b6-bfee-c29e22cc75d4", name="API Management APIs should use only encrypted protocols"},
{ id="c15dcc82-b93c-4dcb-9332-fbf121685b54", name="API Management calls to API backends should be authenticated"},
{ id="b741306c-968e-4b67-b916-5675e5c709f4", name="API Management direct management endpoint should not be enabled"},
{ id="92bb331d-ac71-416a-8c91-02f2cb734ce4", name="API Management calls to API backends should not bypass certificate thumbprint or name validation"},
{ id="73ef9241-5d81-4cd4-b483-8443d1730fe5", name="API Management service should use a SKU that supports virtual networks"},
{ id="549814b6-3212-4203-bdc8-1548d342fb67", name="API Management minimum API version should be set to 2019-12-01 or higher"},
{ id="3aa03346-d8c5-4994-a5bc-7652c2a2aef1", name="API Management subscriptions should not be scoped to all APIs"},
{ id="eb4d34ab-0929-491c-bbf3-61e13da19f9a", name="App Service Environment should be provisioned with latest versions"},
{ id="801543d1-1953-4a90-b8b0-8cf6d41473a5", name="App Service apps should enable configuration routing to Azure Virtual Network"},
{ id="f5c0bfb3-acea-47b1-b477-b0edcdf6edc1", name="App Service app slots should enable outbound non-RFC 1918 traffic to Azure Virtual Network"},
{ id="a691eacb-474d-47e4-b287-b4813ca44222", name="App Service apps should enable outbound non-RFC 1918 traffic to Azure Virtual Network"},
{ id="5747353b-1ca9-42c1-a4dd-b874b894f3d4", name="App Service app slots should enable configuration routing to Azure Virtual Network"},
{ id="546fe8d2-368d-4029-a418-6af48a7f61e5", name="App Service apps should use a SKU that supports private link"},
{ id="6d02d2f7-e38b-4bdc-96f3-adc0a8726abc", name="Hotpatch should be enabled for Windows Server Azure Edition VMs"},
{ id="48c5f1cb-14ad-4797-8e3b-f78ab3f8d700", name="Azure Automation account should have local authentication method disabled"},
{ id="3657f5a0-770e-44a3-b44e-9431ba1e9735", name="Automation account variables should be encrypted"},
{ id="1e66c121-a66a-4b1f-9b83-0fd99bf0fc2d", name="Key vaults should have soft delete enabled"},
{ id="0b60c0b2-2dc2-4e1c-b5c9-abbed971de53", name="Key vaults should have deletion protection enabled"},
{ id="86810a98-8e91-4a44-8386-ec66d0de5d57", name="Azure Key Vault Managed HSM keys using RSA cryptography should have a specified minimum key size"},
{ id="12d4fa5e-1f9f-4c21-97a9-b99b3c6611b5", name="Azure Key Vault should use RBAC permission model"},
{ id="c39ba22d-4428-4149-b981-70acb31fc383", name="Azure Key Vault Managed HSM should have purge protection enabled"},
{ id="1d478a74-21ba-4b9f-9d8f-8e6fced0eec5", name="Azure Key Vault Managed HSM keys should have an expiration date"},
{ id="1151cede-290b-4ba0-8b38-0ad145ac888f", name="Certificates should use allowed key types"},
{ id="bd78111f-4953-4367-9fd5-7e08808b54bf", name="Certificates using elliptic curve cryptography should have allowed curve names"},
{ id="75c4f823-d65c-4f29-a733-01d0077fdbcb", name="Keys should be the specified cryptographic type RSA or EC"},
{ id="ff25f3c8-b739-4538-9d07-3d6d25cfb255", name="Keys using elliptic curve cryptography should have the specified curve names"},
{ id="75262d3e-ba4a-4f43-85f8-9f72c090e5e3", name="Secrets should have content type set"},
{ id="ad27588c-0198-4c84-81ef-08efd0274653", name="Azure Key Vault Managed HSM Keys should have more than the specified number of days before expiration"},
{ id="e58fd0c1-feac-4d12-92db-0a7e9421f53e", name="Azure Key Vault Managed HSM keys using elliptic curve cryptography should have the specified curve names"},
{ id="6164527b-e1ee-4882-8673-572f425f5e0a", name="Bot Service endpoint should be a valid HTTPS URI"},
{ id="52152f42-0dda-40d9-976e-abb1acdd611e", name="Bot Service should have isolated mode enabled"},
{ id="ffea632e-4e3a-4424-bf78-10e179bb2e1a", name="Bot Service should have local authentication methods disabled"},
{ id="a049bf77-880b-470f-ba6d-9f21c530cf83", name="Azure AI Search service should use a SKU that supports private link"},
{ id="6300012e-e9a4-4649-b41f-a85f5c43be91", name="Azure AI Search services should have local authentication methods disabled"},
{ id="fe3fd216-4f83-4fc1-8984-2bbec80a3418", name="Cognitive Services accounts should use a managed identity"},
{ id="46aa9b05-0e60-4eae-a88b-1e9d374fa515", name="Cognitive Services accounts should use customer owned storage"},
{ id="fc4d8e41-e223-45ea-9bf5-eada37891d87", name="Virtual machines and virtual machine scale sets should have encryption at host enabled"},
{ id="8b346db6-85af-419b-8557-92cee2c0f9bb", name="Container App environments should use network injection"},
{ id="b874ab2d-72dd-47f1-8cb5-4a306478a4e7", name="Managed Identity should be enabled for Container Apps"},
{ id="8af8f826-edcb-4178-b35f-851ea6fea615", name="Azure Container Instance container group should deploy into a virtual network"},
{ id="42781ec6-6127-4c30-bdfa-fb423a0047d3", name="Container registries should have ARM audience token authentication disabled."},
{ id="bd560fc0-3c69-498a-ae9f-aa8eb7de0e13", name="Container registries should have SKUs that support Private Links"},
{ id="9f2dea28-e834-476c-99c5-3507b4728395", name="Container registries should have anonymous authentication disabled."},
{ id="524b0254-c285-4903-bee6-bb8126cde579", name="Container registries should have exports disabled"},
{ id="dc921057-6b28-4fbe-9b83-f7bec05db6c2", name="Container registries should have local admin account disabled."},
{ id="ff05e24e-195c-447e-b322-5e90c9f9f366", name="Container registries should have repository scoped access token disabled."},
{ id="d0793b48-0edc-4296-a390-4c75d1bdfd71", name="Container registries should not allow unrestricted network access"},
{ id="862e97cf-49fc-4a5c-9de4-40d4e2e7c8eb", name="Azure Cosmos DB accounts should have firewall rules"},
{ id="5450f5bd-9c72-4390-a9c4-a7aba4edfdd2", name="Cosmos DB database accounts should have local authentication methods disabled"},
{ id="1fec9658-933f-4b3e-bc95-913ed22d012b", name="Azure Data Explorer should use a SKU that supports private link"},
{ id="ec068d99-e9c7-401f-8cef-5bdde4e6ccf1", name="Double encryption should be enabled on Azure Data Explorer"},
{ id="f4b53539-8df9-40e4-86c6-6b607703bd4e", name="Disk encryption should be enabled on Azure Data Explorer"},
{ id="f78ccdb4-7bf4-4106-8647-270491d2978a", name="Azure Data Factory linked services should use system-assigned managed identity authentication when it is supported"},
{ id="77d40665-3120-4348-b539-3192ec808307", name="Azure Data Factory should use a Git repository for source control"},
{ id="127ef6d7-242f-43b3-9eef-947faf1725d0", name="Azure Data Factory linked services should use Key Vault for storing secrets"},
{ id="0088bc63-6dee-4a9c-9d29-91cfdc848952", name="SQL Server Integration Services integration runtimes on Azure Data Factory should be joined to a virtual network"},
{ id="ae9fb87f-8a17-4428-94a4-8135d431055c", name="Azure Event Grid topics should have local authentication methods disabled"},
{ id="8632b003-3545-4b29-85e6-b2b96773df1e", name="Azure Event Grid partner namespaces should have local authentication methods disabled"},
{ id="8bfadddb-ee1c-4639-8911-a38cb8e0b3bd", name="Azure Event Grid domains should have local authentication methods disabled"},
{ id="836cd60e-87f3-4e6a-a27c-29d687f01a4c", name="Event Hub namespaces should have double encryption enabled"},
{ id="5d4e3c65-4873-47be-94f3-6f8b953a3598", name="Azure Event Hub namespaces should have local authentication methods disabled"},
{ id="b278e460-7cfc-4451-8294-cccc40a940d7", name="All authorization rules except RootManageSharedAccessKey should be removed from Event Hub namespace"},
{ id="65280eef-c8b4-425e-9aec-af55e55bf581", name="Kubernetes cluster should not use naked pods"},
{ id="9f061a12-e40d-4183-a00e-171812443373", name="Kubernetes clusters should not use the default namespace"},
{ id="3fc4dc25-5baf-40d8-9b05-7fe74c1bc64e", name="Kubernetes clusters should use internal load balancers"},
{ id="41425d9f-d1a5-499a-9932-f8ed8453932c", name="Temp disks and cache for agent node pools in Azure Kubernetes Service clusters should be encrypted at host"},
{ id="c26596ff-4d70-4e6a-9a30-c2506bd2f80c", name="Kubernetes cluster containers should only use allowed capabilities"},
{ id="1c6e92c9-99f0-4e55-9cf2-0c234dc48f99", name="Kubernetes clusters should not allow container privilege escalation"},
{ id="95edb821-ddaf-4404-9732-666045e056b4", name="Kubernetes cluster should not allow privileged containers"},
{ id="b1a9997f-2883-4f12-bdff-2280f99b5915", name="Ensure cluster containers have readiness or liveness probes configured"},
{ id="040732e8-d947-40b8-95d6-854c95024bf8", name="Azure Kubernetes Service Private Clusters should be enabled"},
{ id="993c2fcd-2b29-49d2-9eb0-df2c3a730c32", name="Azure Kubernetes Service Clusters should have local authentication methods disabled"},
{ id="e96a9a5f-07ca-471b-9bc5-6a0f33cbd68f", name="Azure Machine Learning Computes should have local authentication methods disabled"},
{ id="5f0c7d88-c7de-45b8-ac49-db49e72eaa78", name="Azure Machine Learning workspaces should use user-assigned managed identity"},
{ id="679ddf89-ab8f-48a5-9029-e76054077449", name="Azure Machine Learning Compute Instance should have idle shutdown."},
{ id="e413671a-dd10-4cc1-a943-45b598596cb7", name="Azure Machine Learning workspaces should enable V1LegacyMode to support network isolation backward compatibility"},
{ id="3a58212a-c829-4f13-9872-6371df2fd0b4", name="Infrastructure encryption should be enabled for Azure Database for MySQL servers"},
{ id="35f9c03a-cc27-418e-9c0c-539ff999d010", name="Gateway subnets should not be configured with a network security group"},
{ id="21a6bc25-125e-4d13-b82d-2e19b7208ab7", name="VPN gateways should use only Azure Active Directory (Azure AD) authentication for point-to-site users"},
{ id="055aa869-bc98-4af8-bafc-23f1ab6ffe2c", name="Azure Web Application Firewall should be enabled for Azure Front Door entry-points"},
{ id="12430be1-6cc8-4527-a9a8-e3d38f250096", name="Web Application Firewall (WAF) should use the specified mode for Application Gateway"},
{ id="425bea59-a659-4cbb-8d31-34499bd030b8", name="Web Application Firewall (WAF) should use the specified mode for Azure Front Door Service"},
{ id="88c0b9da-ce96-4b03-9635-f29a937e2900", name="Network interfaces should disable IP forwarding"},
{ id="83a86a26-fd1f-447c-b59d-e51f44264114", name="Network interfaces should not have public IPs"},
{ id="564feb30-bf6a-4854-b4bb-0d2d2d1e6c66", name="Web Application Firewall (WAF) should be enabled for Application Gateway"},
{ id="71ef260a-8f18-47b7-abcb-62d0673d94dc", name="Azure AI Services resources should have key access disabled (disable local authentication)"},
{ id="037eea7a-bd0a-46c5-9a66-03aea78705d3", name="Azure AI Services resources should restrict network access"},
{ id="a1817ec0-a368-432a-8057-8371e17ac6ee", name="All authorization rules except RootManageSharedAccessKey should be removed from Service Bus namespace"},
{ id="ebaf4f25-a4e8-415f-86a8-42d9155bef0b", name="Service Bus namespaces should have double encryption enabled"},
{ id="cfb11c26-f069-4c14-8e36-56c394dae5af", name="Azure Service Bus namespaces should have local authentication methods disabled"},
{ id="abda6d70-9778-44e7-84a8-06713e6db027", name="Azure SQL Database should have Microsoft Entra-only authentication enabled during creation"},
{ id="78215662-041e-49ed-a9dd-5385911b3a1f", name="Azure SQL Managed Instances should have Microsoft Entra-only authentication enabled during creation"},
{ id="bfecdea6-31c4-4045-ad42-71b9dc87247d", name="Storage account encryption scopes should use double encryption for data at rest"},
{ id="92a89a79-6c52-4a7e-a03f-61306fc49312", name="Storage accounts should prevent cross tenant object replication"},
{ id="8c6a50c6-9ffd-4ae7-986f-5fa6111f9a54", name="Storage accounts should prevent shared key access"},
{ id="4733ea7b-a883-42fe-8cac-97454c2a9e4a", name="Storage accounts should have infrastructure encryption"},
{ id="37e0d2fe-28a5-43d6-a273-67d37d1f5606", name="Storage accounts should be migrated to new Azure Resource Manager resources"},
{ id="34c877ad-507e-4c82-993e-3452a6e0ad3c", name="Storage accounts should restrict network access"},
{ id="2a1a9cdf-e04d-429a-8416-3bfb72a1b26f", name="Storage accounts should restrict network access using virtual network rules"},
{ id="044985bb-afe1-42cd-8a36-9d5d42424537", name="Storage account keys should not be expired"},
{ id="3a003702-13d2-4679-941b-937e58c443f0", name="Synapse managed private endpoints should only connect to resources in approved Azure Active Directory tenants"},
{ id="3484ce98-c0c5-4c83-994b-c5ac24785218", name="Azure Synapse workspaces should allow outbound data traffic only to approved targets"},
{ id="2d9dbfa3-927b-4cf0-9d0f-08747f971650", name="Managed workspace virtual network on Azure Synapse workspaces should be enabled"},
{ id="2158ddbe-fefa-408e-b43f-d4faef8ff3b8", name="Synapse Workspaces should use only Microsoft Entra identities for authentication during workspace creation"},
{ id="797b37f7-06b8-444c-b1ad-fc62867f335a", name="Azure Cosmos DB should disable public network access"},
{ id="405c5871-3e91-4644-8a63-58e19d68ff5b", name="Azure Key Vault should disable public network access"},
{ id="1b8ca024-1d5c-4dec-8995-b1a932b41780", name="Public network access on Azure SQL Database should be disabled"},
{ id="b2982f36-99f2-4db5-8eff-283140c09693", name="Storage accounts should disable public network access"},
{ id="0fdf0491-d080-4575-b627-ad0e843cba0f", name="Public network access should be disabled for Container registries"},
{ id="21a8cd35-125e-4d13-b82d-2e19b7208bb7", name="Public network access should be disabled for Azure File Sync"},
{ id="5e1de0e3-42cb-4ebc-a86d-61d0c619ca48", name="Public network access should be disabled for PostgreSQL flexible servers"},
{ id="b52376f7-9612-48a1-81cd-1ffe4b61032c", name="Public network access should be disabled for PostgreSQL servers"},
{ id="c9299215-ae47-4f50-9c54-8a392f68a052", name="Public network access should be disabled for MySQL flexible servers"},
{ id="74c5a0ae-5e48-4738-b093-65e23a060488", name="Public network access should be disabled for Batch accounts"},
{ id="fdccbe47-f3e3-4213-ad5d-ea459b2fa077", name="Public network access should be disabled for MariaDB servers"},
{ id="438c38d2-3772-465a-a9cc-7a6666a275ce", name="Azure Machine Learning Workspaces should disable public network access"},
{ id="470baccb-7e51-4549-8b1a-3e5be069f663", name="Azure Cache for Redis should disable public network access"},
{ id="5e8168db-69e3-4beb-9822-57cb59202a9d", name="Bot Service should have public network access disabled"},
{ id="955a914f-bf86-4f0e-acd5-e0766b0efcb6", name="Automation accounts should disable public network access"},
{ id="3d9f5e4c-9947-4579-9539-2a7695fbc187", name="App Configuration should disable public network access"},
{ id="969ac98b-88a8-449f-883c-2e9adb123127", name="Function apps should disable public network access"},
{ id="11c82d0c-db9f-4d7b-97c5-f3f9aa957da2", name="Function app slots should disable public network access"},
{ id="2d048aca-6479-4923-88f5-e2ac295d9af3", name="App Service Environment apps should not be reachable over public internet"},
{ id="1b5ef780-c53c-4a64-87f3-bb9c8c8094ba", name="App Service apps should disable public network access"},
{ id="d074ddf8-01a5-4b5e-a2b8-964aed452c0a", name="Container Apps environment should disable public network access"},
{ id="783ea2a8-b8fd-46be-896a-9ae79643a0b1", name="Container Apps should disable external network access"},
{ id="9ebbbba3-4d65-4da9-bb67-b22cfaaff090", name="Azure Recovery Services vaults should disable public network access"},
{ id="701a595d-38fb-4a66-ae6d-fb3735217622", name="App Service app slots should disable public network access"},
{ id="ee980b6d-0eca-4501-8d54-f6290fd512c3", name="Azure AI Search services should disable public network access"},
{ id="43bc7be6-5e69-4b0d-a2bb-e815557ca673", name="Public network access on Azure Data Explorer should be disabled"},
{ id="1cf164be-6819-4a50-b8fa-4bcaa4f98fb6", name="Public network access on Azure Data Factory should be disabled"},
{ id="f8f774be-6aee-492a-9e29-486ef81f3a68", name="Azure Event Grid domains should disable public network access"},
{ id="1adadefe-5f21-44f7-b931-a59b54ccdb45", name="Azure Event Grid topics should disable public network access"},
{ id="0602787f-9896-402a-a6e1-39ee63ee435e", name="Event Hub Namespaces should disable public network access"},
{ id="19ea9d63-adee-4431-a95e-1913c6c1c75f", name="Azure Key Vault Managed HSM should disable public network access"},
{ id="d9844e8a-1437-4aeb-a32c-0c992f056095", name="Public network access should be disabled for MySQL servers"},
{ id="cbd11fd3-3002-4907-b6c8-579f0e700e13", name="Service Bus Namespaces should disable public network access"},
{ id="9dfea752-dd46-4766-aed1-c355fa93fb91", name="Azure SQL Managed Instances should disable public network access"},
{ id="4fa4b6c0-31ca-4c0d-b10d-24b96f62a751", name="Storage account public access should be disallowed"},
{ id="38d8df46-cf4e-4073-8e03-48c24b29de0d", name="Azure Synapse workspaces should disable public network access"},
{ id="87ac3038-c07a-4b92-860d-29e270a4f3cd", name="Azure Virtual Desktop workspaces should disable public network access"},
{ id="c25dcf31-878f-4eba-98eb-0818fdc6a334", name="Azure Virtual Desktop hostpools should disable public network access"},
{ id="e8775d5a-73b7-4977-a39b-833ef0114628", name="Azure Managed Grafana workspaces should disable public network access"},
{ id="bd876905-5b84-4f73-ab2d-2e7a7c4568d9", name="Machines should be configured to periodically check for missing system updates"},
{ id="22bee202-a82f-4305-9a2a-6d7f44d4dedb", name="Only secure connections to your Azure Cache for Redis should be enabled"},
{ id="24fba194-95d6-48c0-aea7-f65bf859c598", name="Infrastructure encryption should be enabled for Azure Database for PostgreSQL servers"},
{ id="404c3081-a854-4457-ae30-26a93ef643f9", name="Secure transfer to storage accounts should be enabled"},
{ id="c9d007d0-c057-4772-b18c-01e546713bcd", name="Storage accounts should allow access from trusted Microsoft services"},
{ id="fd9903f1-38c2-4d36-8e44-5c1c20c561e8", name="Storage accounts should prevent shared key access (excluding storage accounts created by Databricks)"},
{ id="db4f9b05-5ffd-4b34-b714-3c710dbb3fd6", name="Storage accounts should restrict network access using virtual network rules (excluding storage accounts created by Databricks)"}
  ]
}

resource "azurerm_policy_set_definition" "ims-builtin-prod-initiative-190" {
  name                = "ims-builtin-prod-initiative-190"
  display_name        = "ims-builtin-prod-initiative-190"
  policy_type         = "Custom"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

 # depends_on = [
 # azurerm_management_group.IMS-Root
 # ]

  dynamic "policy_definition_reference" {
    for_each = local.ims_builtin_prod_policy_ids
    content {
      policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/${policy_definition_reference.value.id}"
      reference_id         = policy_definition_reference.value.name
      
      parameter_values = contains([
	      "98728c90-32c7-4049-8429-847dc0f4fe37",
        "152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0",
        "55615ac9-af46-4a59-874e-391cc3dfb490",
        "0a075868-4c26-42ef-914c-5bc007359560",
        "8405fdab-1faf-48aa-b702-999c9c172094",
        "1a5b4dca-0b6f-4cf5-907c-56316bc1bf3d",
        "0e80e269-43a4-4ae9-b5bc-178126b8a5cb",
        "a4af4a39-4135-47fb-b175-47fbdf85311d",
        "d6545c6b-dd9d-4265-91e6-0b451e2f1c50",
        "5e5dbe3f-2702-4ffc-8b1e-0cae008a5c71",
        "6d555dd1-86f2-4f1c-8ed7-5abae7c6cbab",
        "ae1b9a8c-dfce-4605-bd91-69213b4a26fc",
        "32e6bbec-16b6-44c2-be37-c5b672d103cf",
        "fe83a0eb-a853-422d-aac2-1bffd182c5d0",
        "cb3738a6-82a2-4a18-b87b-15217b9deff4",
        "f1cc7827-022c-473e-836e-5a51cae0b249",
        "ef619a2c-cc4d-4d03-b2ba-8c94a834d85b",
        "ee7495e7-3ba7-40b6-bfee-c29e22cc75d4",
        "c15dcc82-b93c-4dcb-9332-fbf121685b54",
        "b741306c-968e-4b67-b916-5675e5c709f4",
        "92bb331d-ac71-416a-8c91-02f2cb734ce4",
        "73ef9241-5d81-4cd4-b483-8443d1730fe5",
        "549814b6-3212-4203-bdc8-1548d342fb67",
        "3aa03346-d8c5-4994-a5bc-7652c2a2aef1",
        "eb4d34ab-0929-491c-bbf3-61e13da19f9a",
        "801543d1-1953-4a90-b8b0-8cf6d41473a5",
        "f5c0bfb3-acea-47b1-b477-b0edcdf6edc1",
        "a691eacb-474d-47e4-b287-b4813ca44222",
        "5747353b-1ca9-42c1-a4dd-b874b894f3d4",
        "546fe8d2-368d-4029-a418-6af48a7f61e5",
        "6d02d2f7-e38b-4bdc-96f3-adc0a8726abc",
        "48c5f1cb-14ad-4797-8e3b-f78ab3f8d700",
        "3657f5a0-770e-44a3-b44e-9431ba1e9735",
        "1e66c121-a66a-4b1f-9b83-0fd99bf0fc2d",
        "0b60c0b2-2dc2-4e1c-b5c9-abbed971de53",
        "86810a98-8e91-4a44-8386-ec66d0de5d57",
        "12d4fa5e-1f9f-4c21-97a9-b99b3c6611b5",
        "c39ba22d-4428-4149-b981-70acb31fc383",
        "1d478a74-21ba-4b9f-9d8f-8e6fced0eec5",
        "1151cede-290b-4ba0-8b38-0ad145ac888f",
        "bd78111f-4953-4367-9fd5-7e08808b54bf",
        "75c4f823-d65c-4f29-a733-01d0077fdbcb",
        "ff25f3c8-b739-4538-9d07-3d6d25cfb255",
        "75262d3e-ba4a-4f43-85f8-9f72c090e5e3",
        "ad27588c-0198-4c84-81ef-08efd0274653",
        "e58fd0c1-feac-4d12-92db-0a7e9421f53e",
        "6164527b-e1ee-4882-8673-572f425f5e0a",
        "52152f42-0dda-40d9-976e-abb1acdd611e",
        "ffea632e-4e3a-4424-bf78-10e179bb2e1a",
        "a049bf77-880b-470f-ba6d-9f21c530cf83",
        "6300012e-e9a4-4649-b41f-a85f5c43be91",
        "fe3fd216-4f83-4fc1-8984-2bbec80a3418",
        "46aa9b05-0e60-4eae-a88b-1e9d374fa515",
        "fc4d8e41-e223-45ea-9bf5-eada37891d87",
        "8b346db6-85af-419b-8557-92cee2c0f9bb",
        "b874ab2d-72dd-47f1-8cb5-4a306478a4e7",
        "8af8f826-edcb-4178-b35f-851ea6fea615",
        "42781ec6-6127-4c30-bdfa-fb423a0047d3",
        "bd560fc0-3c69-498a-ae9f-aa8eb7de0e13",
        "9f2dea28-e834-476c-99c5-3507b4728395",
        "524b0254-c285-4903-bee6-bb8126cde579",
        "dc921057-6b28-4fbe-9b83-f7bec05db6c2",
        "ff05e24e-195c-447e-b322-5e90c9f9f366",
        "d0793b48-0edc-4296-a390-4c75d1bdfd71",
        "862e97cf-49fc-4a5c-9de4-40d4e2e7c8eb",
        "5450f5bd-9c72-4390-a9c4-a7aba4edfdd2",
        "1fec9658-933f-4b3e-bc95-913ed22d012b",
        "ec068d99-e9c7-401f-8cef-5bdde4e6ccf1",
        "f4b53539-8df9-40e4-86c6-6b607703bd4e",
        "f78ccdb4-7bf4-4106-8647-270491d2978a",
        "77d40665-3120-4348-b539-3192ec808307",
        "127ef6d7-242f-43b3-9eef-947faf1725d0",
        "0088bc63-6dee-4a9c-9d29-91cfdc848952",
        "ae9fb87f-8a17-4428-94a4-8135d431055c",
        "8632b003-3545-4b29-85e6-b2b96773df1e",
        "8bfadddb-ee1c-4639-8911-a38cb8e0b3bd",
        "836cd60e-87f3-4e6a-a27c-29d687f01a4c",
        "5d4e3c65-4873-47be-94f3-6f8b953a3598",
        "b278e460-7cfc-4451-8294-cccc40a940d7",
        "65280eef-c8b4-425e-9aec-af55e55bf581",
        "9f061a12-e40d-4183-a00e-171812443373",
        "3fc4dc25-5baf-40d8-9b05-7fe74c1bc64e",
        "41425d9f-d1a5-499a-9932-f8ed8453932c",
        "c26596ff-4d70-4e6a-9a30-c2506bd2f80c",
        "1c6e92c9-99f0-4e55-9cf2-0c234dc48f99",
        "95edb821-ddaf-4404-9732-666045e056b4",
        "b1a9997f-2883-4f12-bdff-2280f99b5915",
        "040732e8-d947-40b8-95d6-854c95024bf8",
        "993c2fcd-2b29-49d2-9eb0-df2c3a730c32",
        "e96a9a5f-07ca-471b-9bc5-6a0f33cbd68f",
        "5f0c7d88-c7de-45b8-ac49-db49e72eaa78",
        "679ddf89-ab8f-48a5-9029-e76054077449",
        "e413671a-dd10-4cc1-a943-45b598596cb7",
        "3a58212a-c829-4f13-9872-6371df2fd0b4",
        "21a6bc25-125e-4d13-b82d-2e19b7208ab7",
        "055aa869-bc98-4af8-bafc-23f1ab6ffe2c",
        "12430be1-6cc8-4527-a9a8-e3d38f250096",
        "425bea59-a659-4cbb-8d31-34499bd030b8",
        "564feb30-bf6a-4854-b4bb-0d2d2d1e6c66",
        "71ef260a-8f18-47b7-abcb-62d0673d94dc",
        "037eea7a-bd0a-46c5-9a66-03aea78705d3",
        "a1817ec0-a368-432a-8057-8371e17ac6ee",
        "ebaf4f25-a4e8-415f-86a8-42d9155bef0b",
        "cfb11c26-f069-4c14-8e36-56c394dae5af",
        "abda6d70-9778-44e7-84a8-06713e6db027",
        "78215662-041e-49ed-a9dd-5385911b3a1f",
        "bfecdea6-31c4-4045-ad42-71b9dc87247d",
        "92a89a79-6c52-4a7e-a03f-61306fc49312",
        "8c6a50c6-9ffd-4ae7-986f-5fa6111f9a54",
        "4733ea7b-a883-42fe-8cac-97454c2a9e4a",
        "37e0d2fe-28a5-43d6-a273-67d37d1f5606",
        "34c877ad-507e-4c82-993e-3452a6e0ad3c",
        "2a1a9cdf-e04d-429a-8416-3bfb72a1b26f",
        "044985bb-afe1-42cd-8a36-9d5d42424537",
        "3a003702-13d2-4679-941b-937e58c443f0",
        "3484ce98-c0c5-4c83-994b-c5ac24785218",
        "2d9dbfa3-927b-4cf0-9d0f-08747f971650",
        "2158ddbe-fefa-408e-b43f-d4faef8ff3b8",
        "797b37f7-06b8-444c-b1ad-fc62867f335a",
        "405c5871-3e91-4644-8a63-58e19d68ff5b",
        "1b8ca024-1d5c-4dec-8995-b1a932b41780",
        "b2982f36-99f2-4db5-8eff-283140c09693",
        "0fdf0491-d080-4575-b627-ad0e843cba0f",
        "21a8cd35-125e-4d13-b82d-2e19b7208bb7",
        "5e1de0e3-42cb-4ebc-a86d-61d0c619ca48",
        "b52376f7-9612-48a1-81cd-1ffe4b61032c",
        "c9299215-ae47-4f50-9c54-8a392f68a052",
        "74c5a0ae-5e48-4738-b093-65e23a060488",
        "fdccbe47-f3e3-4213-ad5d-ea459b2fa077",
        "438c38d2-3772-465a-a9cc-7a6666a275ce",
        "470baccb-7e51-4549-8b1a-3e5be069f663",
        "5e8168db-69e3-4beb-9822-57cb59202a9d",
        "955a914f-bf86-4f0e-acd5-e0766b0efcb6",
        "3d9f5e4c-9947-4579-9539-2a7695fbc187",
        "969ac98b-88a8-449f-883c-2e9adb123127",
        "11c82d0c-db9f-4d7b-97c5-f3f9aa957da2",
        "2d048aca-6479-4923-88f5-e2ac295d9af3",
        "1b5ef780-c53c-4a64-87f3-bb9c8c8094ba",
        "d074ddf8-01a5-4b5e-a2b8-964aed452c0a",
        "783ea2a8-b8fd-46be-896a-9ae79643a0b1",
        "9ebbbba3-4d65-4da9-bb67-b22cfaaff090",
        "701a595d-38fb-4a66-ae6d-fb3735217622",
        "ee980b6d-0eca-4501-8d54-f6290fd512c3",
        "43bc7be6-5e69-4b0d-a2bb-e815557ca673",
        "1cf164be-6819-4a50-b8fa-4bcaa4f98fb6",
        "f8f774be-6aee-492a-9e29-486ef81f3a68",
        "1adadefe-5f21-44f7-b931-a59b54ccdb45",
        "0602787f-9896-402a-a6e1-39ee63ee435e",
        "19ea9d63-adee-4431-a95e-1913c6c1c75f",
        "d9844e8a-1437-4aeb-a32c-0c992f056095",
        "cbd11fd3-3002-4907-b6c8-579f0e700e13",
        "9dfea752-dd46-4766-aed1-c355fa93fb91",
        "4fa4b6c0-31ca-4c0d-b10d-24b96f62a751",
        "38d8df46-cf4e-4073-8e03-48c24b29de0d",
        "87ac3038-c07a-4b92-860d-29e270a4f3cd",
        "c25dcf31-878f-4eba-98eb-0818fdc6a334",
        "e8775d5a-73b7-4977-a39b-833ef0114628",
	      "bd876905-5b84-4f73-ab2d-2e7a7c4568d9",
	      "22bee202-a82f-4305-9a2a-6d7f44d4dedb",
	      "24fba194-95d6-48c0-aea7-f65bf859c598",
	      "404c3081-a854-4457-ae30-26a93ef643f9",
	      "c9d007d0-c057-4772-b18c-01e546713bcd",
	      "fd9903f1-38c2-4d36-8e44-5c1c20c561e8",
	      "db4f9b05-5ffd-4b34-b714-3c710dbb3fd6"
        
        ], 
	policy_definition_reference.value.id) ? jsonencode({
        effect = { value = "Deny" }
      }) : null
    }
  }
}

# Default option for 35f9c03a-cc27-418e-9c0c-539ff999d010, 88c0b9da-ce96-4b03-9635-f29a937e2900, 83a86a26-fd1f-447c-b59d-e51f44264114 is "deny"

#Initiative ims-builtin-prod-location-initiative 2-169
# Create ims-builtin-prod-initiative-logs-10 with built-in definitions, assigned to IMS_Root MG
resource "azurerm_policy_set_definition" "ims-builtin-prod-initiative-logs-10" {
  name                = "ims-builtin-prod-initiative-logs-10"
  display_name        = "ims-builtin-prod-initiative-logs-10"
  policy_type         = "Custom"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"
  

#depends_on = [
 #   azurerm_management_group.IMS-Root
#  ]
  
  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c"
    reference_id = "AllowedLocations"
    parameter_values = jsonencode({
      listOfAllowedLocations = {
        value = ["northeurope", "westeurope"]
      }
    })
  }

  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/e765b5de-1225-4ba3-bd56-1ac6695af988"
    reference_id = "AllowedLocationsForResourceGroups"
    parameter_values = jsonencode({
      listOfAllowedLocations = {
        value = ["northeurope", "westeurope"]
      }
    })
   }
}

#Initiative ims-custom-corp-initiative-66-77
# Create ims-custom-corp-initiative-66 with custom definitions
resource "azurerm_policy_set_definition" "ims-custom-corp-initiative-66" {
  name                = "ims-custom-corp-initiative-66"
  display_name        = "ims-custom-corp-initiative-66"
  description         = "Initiative including custom policies for corp"
  policy_type         = "Custom"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

depends_on = [
  # azurerm_management_group.IMS-Root,
  azurerm_policy_definition.deploy_mysql_ssl_min_tls,
  azurerm_policy_definition.postgresql_min_tls_and_ssl,
  azurerm_policy_definition.deploy_storage_ssl_enforcement,
  azurerm_policy_definition.logic_apps_latest_tls,
  azurerm_policy_definition.deploy_default_budget,
  azurerm_policy_definition.deploy_sql_database_auditing_settings,
  azurerm_policy_definition.deploy_sql_security_alert_policies,
  azurerm_policy_definition.deploy_vm_auto_shutdown,
  azurerm_policy_definition.modify_nsg,
  azurerm_policy_definition.sql_managed_instance_min_tls,
  azurerm_policy_definition.deploy_sql_min_tls,
  azurerm_policy_definition.audit_subnet_without_penp,
  azurerm_policy_definition.defender_iot_hub_on,
  azurerm_policy_definition.app_insights_configured,
  azurerm_policy_definition.readonly_locks_storage_accounts,
  azurerm_policy_definition.udp_access_from_internet_restricted,
  azurerm_policy_definition.enable_key_rotation_reminders,
  azurerm_policy_definition.http_https_access_from_internet_restricted,
  azurerm_policy_definition.public_ip_addresses_periodic_evaluation,
  azurerm_policy_definition.azure_bastion_host_exists,
  azurerm_policy_definition.entra_authentication_enabled,
  azurerm_policy_definition.mfa_enabled_identities_vm_access,
  azurerm_policy_definition.system_assigned_managed_identity_on,
  azurerm_policy_definition.audit_log_enabled_mysql,
  azurerm_policy_definition.number_of_methods_required_to_reset,
  azurerm_policy_definition.register_with_aad_enabled_app_service,
  azurerm_policy_definition.storage_account_access_keys_regenerated,
  azurerm_policy_definition.smb_channel_encryption_aes256gcm,
  azurerm_policy_definition.mfa_policy_admin_groups,
  azurerm_policy_definition.mfa_required_risky_signins,
  azurerm_policy_definition.mfa_required_admin_portals,
  azurerm_policy_definition.account_lockout_threshold,
  azurerm_policy_definition.sas_tokens_expire_within_hour,
  azurerm_policy_definition.account_lockout_duration_seconds,
  azurerm_policy_definition.restrict_access_entra_admin_center,
  azurerm_policy_definition.custom_bad_password_list_enforce,
  azurerm_policy_definition.restrict_access_groups_features_access_pane,
  azurerm_policy_definition.fewer_than_5_global_admins,
  azurerm_policy_definition.soft_delete_enabled_blob_storage,
  azurerm_policy_definition.cloud_security_benchmark_not_disabled,
  azurerm_policy_definition.number_of_days_reconfirm_auth,
  azurerm_policy_definition.all_users_roles_set_to_owner,
  azurerm_policy_definition.managed_identity_used_for_azure_services,
  azurerm_policy_definition.notify_users_on_password_resets,
  azurerm_policy_definition.notify_admins_on_password_reset,
  azurerm_policy_definition.security_defaults_enabled,
  azurerm_policy_definition.logfiles_retention_days_postgresql,
  azurerm_policy_definition.defender_cloud_apps_integration,
  azurerm_policy_definition.require_secure_transport_mysql,
  azurerm_policy_definition.tls_version_mysql_flexible_server,
  azurerm_policy_definition.audit_log_events_connection_mysql,
  azurerm_policy_definition.enable_data_access_auth_mode,
  azurerm_policy_definition.key_vaults_used_to_store_secrets,
  azurerm_policy_definition.resource_locks_mission_critical,
  azurerm_policy_definition.vulnerability_assessment_for_machines,
  azurerm_policy_definition.endpoint_protection_component_on,
  azurerm_policy_definition.agentless_scanning_for_machines,
  azurerm_policy_definition.file_integrity_monitoring_on,
  azurerm_policy_definition.locked_immutability_policy_blob,
  azurerm_policy_definition.arm_delete_locks_storage_accounts,
  azurerm_policy_definition.diagnostic_setting_subscription_activity_logs,
  azurerm_policy_definition.defender_easm_enabled,
  azurerm_policy_definition.http_logs_enabled_appservice,
  azurerm_policy_definition.enable_soft_delete_for_blobs,
  azurerm_policy_definition.enable_soft_delete_for_containers,
  azurerm_policy_definition.enable_soft_delete_for_file_shares
    
  /*
#  Additional Parameters Required for these custom definitions
  azurerm_policy_definition.deploy_custom_route_table,
  azurerm_policy_definition.deploy_ddos_network_protection,
  azurerm_policy_definition.deploy_firewall_policy,
  azurerm_policy_definition.deploy_asc_security_contacts,
  azurerm_policy_definition.deploy_sql_vulnerability_assessments,
  azurerm_policy_definition.deploy_vnet_hubspoke,
  azurerm_policy_definition.deploy_windows_domainjoin_extension_with_keyvault,
  azurerm_policy_definition.private_dns_generic,
  azurerm_policy_definition.modify_udr,
  azurerm_policy_definition.trusted_locations_defined,
  azurerm_policy_definition.custom_role_administer_resource_locks,
*/

]
 
 # Add custom definitions with default effect to the initiative
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-MySQL-sslEnforcement"
    reference_id         = "Deploy-MySQL-sslEnforcement"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-PostgreSQL-sslEnforcement"
    reference_id         = "Deploy-PostgreSQL-sslEnforcement"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-Storage-sslEnforcement"
    reference_id         = "Deploy-Storage-sslEnforcement"
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Configure-Logic-Apps-Latest-TLS" 
    reference_id = "Configure-Logic-Apps-Latest-TLS" 
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-Budget"
    reference_id         = "Deploy-Budget"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-Sql-AuditingSettings"
    reference_id         = "Deploy-Sql-AuditingSettings"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-Sql-SecurityAlertPolicies"
    reference_id         = "Deploy-Sql-SecurityAlertPolicies"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-Vm-autoShutdown"
    reference_id         = "Deploy-Vm-autoShutdown"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Modify-NSG"
    reference_id         = "Modify-NSG"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-SqlMi-minTLS"
    reference_id         = "Deploy-SqlMi-minTLS"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-SQL-minTLS"
    reference_id         = "Deploy-SQL-minTLS"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Audit-Subnet-Without-Penp"
    reference_id         = "Audit-Subnet-Without-Penp"
  }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Defender-IoT-Hub-On" 
    reference_id = "Defender-IoT-Hub-On" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/App-Insights-Configured" 
    reference_id = "App-Insights-Configured" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/ReadOnly-Locks-Storage-Accounts" 
    reference_id = "ReadOnly-Locks-Storage-Accounts" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/UDP-Access-From-Internet-Restricted" 
    reference_id = "UDP-Access-From-Internet-Restricted" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Enable-Key-Rotation-Reminders" 
    reference_id = "Enable-Key-Rotation-Reminders" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/HTTP-HTTPS-Access-From-Internet-Restricted" 
    reference_id = "HTTP-HTTPS-Access-From-Internet-Restricted" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Public-IP-Addresses-Periodic-Evaluation" 
    reference_id = "Public-IP-Addresses-Periodic-Evaluation" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Azure-Bastion-Host-Exists" 
    reference_id = "Azure-Bastion-Host-Exists" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Entra-Authentication-Enabled" 
    reference_id = "Entra-Authentication-Enabled" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/MFA-Enabled-Identities-VM-Access" 
    reference_id = "MFA-Enabled-Identities-VM-Access" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/System-Assigned-Managed-Identity-On" 
    reference_id = "System-Assigned-Managed-Identity-On" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Audit-Log-Enabled-MySQL" 
    reference_id = "Audit-Log-Enabled-MySQL" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Number-Of-Methods-Required-To-Reset" 
    reference_id = "Number-Of-Methods-Required-To-Reset" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Register-With-AAD-Enabled-App-Service" 
    reference_id = "Register-With-AAD-Enabled-App-Service" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Storage-Account-Access-Keys-Regenerated" 
    reference_id = "Storage-Account-Access-Keys-Regenerated" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/SMB-Channel-Encryption-AES256GCM" 
    reference_id = "SMB-Channel-Encryption-AES256GCM" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/MFA-Policy-Admin-Groups" 
    reference_id = "MFA-Policy-Admin-Groups" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/MFA-Required-Risky-Signins" 
    reference_id = "MFA-Required-Risky-Signins" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/MFA-Required-Admin-Portals" 
    reference_id = "MFA-Required-Admin-Portals" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Account-Lockout-Threshold" 
    reference_id = "Account-Lockout-Threshold" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/SAS-Tokens-Expire-Within-Hour" 
    reference_id = "SAS-Tokens-Expire-Within-Hour" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Account-Lockout-Duration-Seconds" 
    reference_id = "Account-Lockout-Duration-Seconds" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Restrict-Access-Entra-Admin-Center" 
    reference_id = "Restrict-Access-Entra-Admin-Center" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Custom-Bad-Password-List-Enforce" 
    reference_id = "Custom-Bad-Password-List-Enforce" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Restrict-Access-Groups-Features-Access-Pane" 
    reference_id = "Restrict-Access-Groups-Features-Access-Pane" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Fewer-Than-5-Global-Admins" 
    reference_id = "Fewer-Than-5-Global-Admins" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Soft-Delete-Enabled-Blob-Storage" 
    reference_id = "Soft-Delete-Enabled-Blob-Storage" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Cloud-Security-Benchmark-Not-Disabled" 
    reference_id = "Cloud-Security-Benchmark-Not-Disabled" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Number-Of-Days-Reconfirm-Auth" 
    reference_id = "Number-Of-Days-Reconfirm-Auth" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/All-Users-Roles-Set-To-Owner" 
    reference_id = "All-Users-Roles-Set-To-Owner" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Managed-Identity-Used-For-Azure-Services" 
    reference_id = "Managed-Identity-Used-For-Azure-Services" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Notify-Users-On-Password-Resets" 
    reference_id = "Notify-Users-On-Password-Resets" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Notify-Admins-On-Password-Reset" 
    reference_id = "Notify-Admins-On-Password-Reset" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Security-Defaults-Enabled" 
    reference_id = "Security-Defaults-Enabled" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Logfiles-Retention-Days-PostgreSQL" 
    reference_id = "Logfiles-Retention-Days-PostgreSQL" 
    }
policy_definition_reference { 
  policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Defender-Cloud-Apps-Integration" 
    reference_id = "Defender-Cloud-Apps-Integration" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Require-Secure-Transport-MySQL" 
    reference_id = "Require-Secure-Transport-MySQL" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/TLS-Version-MySQL-Flexible-Server" 
    reference_id = "TLS-Version-MySQL-Flexible-Server" 
    }
policy_definition_reference { 
  policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Audit-Log-Events-Connection-MySQL" 
    reference_id = "Audit-Log-Events-Connection-MySQL" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Enable-Data-Access-Authentication-Mode" 
    reference_id = "Enable-Data-Access-Authentication-Mode" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Key-Vaults-Used-To-Store-Secrets" 
    reference_id = "Key-Vaults-Used-To-Store-Secrets" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Resource-Locks-Mission-Critical" 
    reference_id = "Resource-Locks-Mission-Critical" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Vulnerability-Assessment-For-Machines" 
    reference_id = "Vulnerability-Assessment-For-Machines" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Endpoint-Protection-Component-On" 
    reference_id = "Endpoint-Protection-Component-On" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Agentless-Scanning-For-Machines" 
    reference_id = "Agentless-Scanning-For-Machines" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/File-Integrity-Monitoring-On" 
    reference_id = "File-Integrity-Monitoring-On" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Locked-Immutability-Policy-Blob" 
    reference_id = "Locked-Immutability-Policy-Blob" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/ARM-Delete-Locks-Storage-Accounts" 
    reference_id = "ARM-Delete-Locks-Storage-Accounts" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Diagnostic-Setting-Subscription-Activity-Logs" 
    reference_id = "Diagnostic-Setting-Subscription-Activity-Logs" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Defender-EASM-Enabled" 
    reference_id = "Defender-EASM-Enabled" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/HTTP-Logs-Enabled-AppService" 
    reference_id = "HTTP-Logs-Enabled-AppService" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-Storage-Blob-SoftDelete" 
    reference_id = "Deploy-Storage-Blob-SoftDelete" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-Storage-Container-SoftDelete" 
    reference_id = "Deploy-Storage-Container-SoftDelete" 
    }
policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-Storage-File-SoftDelete" 
    reference_id = "Deploy-Storage-File-SoftDelete" 
    }

#Additional Parameters Required
 /*
  policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-Custom-Route-Table" 
    reference_id = "Deploy-Custom-Route-Table" 
    }
  policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-DDoSProtection" 
    reference_id = "Deploy-DDoSProtection" 
    }
  policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-FirewallPolicy" 
    reference_id = "Deploy-FirewallPolicy" 
    }
  policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-ASC-SecurityContacts" 
    reference_id = "Deploy-ASC-SecurityContacts" 
    }
  policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-Sql-vulnerabilityAssessments" 
    reference_id = "Deploy-Sql-vulnerabilityAssessments" 
    }
  policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-VNET-HubSpoke" 
    reference_id = "Deploy-VNET-HubSpoke" 
    }
  policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-Windows-DomainJoin" 
    reference_id = "Deploy-Windows-DomainJoin" 
    }
  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deploy-Private-DNS-Generic"
    reference_id         = "Deploy-Private-DNS-Generic"
    }
  policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Modify-UDR" 
    reference_id = "Modify-UDR" 
    }
  policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Trusted-Locations-Defined" 
    reference_id = "Trusted-Locations-Defined" 
    }
  policy_definition_reference { 
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Custom-Role-Administer-Resource-Locks" 
    reference_id = "Custom-Role-Administer-Resource-Locks" 
    }
*/
}
#Initiative ims-custom-prod-initiative-33-38
# Create ims-custom-prod-initiative-36 with custom definitions
resource "azurerm_policy_set_definition" "ims-custom-prod-initiative-36" {
  name                = "ims-custom-prod-initiative-36"
  display_name        = "ims-custom-prod-initiative-36"
  description         = "Initiative including custom policies for prod"
  policy_type         = "Custom"
  management_group_id = "/providers/Microsoft.Management/managementGroups/IMS-Root"

depends_on = [
  # azurerm_management_group.IMS-Root,
  azurerm_policy_definition.denyaction_activity_logs,
  azurerm_policy_definition.denyaction_diagnostic_logs,
  azurerm_policy_definition.deny_storageaccount_customdomain,
  azurerm_policy_definition.deny_storage_sftp,
  azurerm_policy_definition.deny_subnet_without_nsg,
  azurerm_policy_definition.deny_subnet_without_udr,
  azurerm_policy_definition.deny_udr_with_specific_nexthop,
  azurerm_policy_definition.restrict_non_admin_tenant_creation,
  azurerm_policy_definition.webapp_client_cert_required,
  azurerm_policy_definition.deny_remember_mfa_on_trusted_devices,
  azurerm_policy_definition.deny_public_network_access_recovery_vaults,
  azurerm_policy_definition.require_mfa_for_azure_management_api,
  azurerm_policy_definition.restrict_subscription_movement,
  azurerm_policy_definition.smb_protocol_version_required,
  azurerm_policy_definition.mfa_policy_for_all_users,
  azurerm_policy_definition.minimum_tls_version_redis,
  azurerm_policy_definition.public_network_access_disabled_redis,
  azurerm_policy_definition.private_vnet_for_container_instances,
  azurerm_policy_definition.deny_basic_consumption_sku,
  azurerm_policy_definition.deny_user_consent_for_applications,
  azurerm_policy_definition.deny_users_can_register_applications,
  azurerm_policy_definition.deny_guest_user_access,
  azurerm_policy_definition.deny_owners_manage_group_membership_requests,
  azurerm_policy_definition.deny_users_create_m365_groups,
  azurerm_policy_definition.cross_region_restore_enabled,
  azurerm_policy_definition.blob_versioning_enabled,
  azurerm_policy_definition.public_network_access_disabled,
  azurerm_policy_definition.soft_delete_azure_file_shares,
  azurerm_policy_definition.soft_delete_blobs_enabled,
  azurerm_policy_definition.force_vnet_encryption,
  azurerm_policy_definition.enforce_ddos_protection_on_vnet,
  azurerm_policy_definition.deny_storage_account_public_access,
  azurerm_policy_definition.deny_key_vault_public_access
  
/*
  azurerm_policy_definition.denyaction_delete_resources,
  azurerm_policy_definition.enforce_storage_encryption,
*/
  ]

# Add custom definitions with deny effect to the initiative
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/DenyAction-ActivityLogs"
    reference_id         = "DenyAction-ActivityLogs"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/DenyAction-DiagnosticLogs"
    reference_id         = "DenyAction-DiagnosticLogs"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-StorageAccount-CustomDomain"
    reference_id         = "Deny-StorageAccount-CustomDomain"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-Storage-SFTP"
    reference_id         = "Deny-Storage-SFTP"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-Subnet-Without-Nsg"
    reference_id         = "Deny-Subnet-Without-Nsg"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-Subnet-Without-Udr"
    reference_id         = "Deny-Subnet-Without-Udr"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-UDR-With-Specific-NextHop"
    reference_id         = "Deny-UDR-With-Specific-NextHop"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Restrict-Non-Admin-Tenant-Creation"
    reference_id         = "Restrict-Non-Admin-Tenant-Creation"
   }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/WebApp-Client-Cert-Required"
    reference_id         = "WebApp-Client-Cert-Required"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-Remember-MFA-On-Trusted-Devices"
    reference_id         = "Deny-Remember-MFA-On-Trusted-Devices"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-Public-Network-Access-Recovery-Vaults"
    reference_id         = "Deny-Public-Network-Access-Recovery-Vaults"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Require-MFA-For-Azure-Management-API"
    reference_id         = "Require-MFA-For-Azure-Management-API"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/restrict_Subscription_Movement"
    reference_id         = "restrict_Subscription_Movement"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/SMB-Protocol-Version-Required"
    reference_id         = "SMB-Protocol-Version-Required"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/MFA-Policy-For-All-Users"
    reference_id         = "MFA-Policy-For-All-Users"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Minimum-TLS-Version-Redis"
    reference_id         = "Minimum-TLS-Version-Redis"
    }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Public-Network-Access-Disabled-Redis"
    reference_id         = "Public-Network-Access-Disabled-Redis"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Private-VNet-For-Container-Instances"
    reference_id         = "Private-VNet-For-Container-Instances"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-Basic-Consumption-SKU"
    reference_id         = "Deny-Basic-Consumption-SKU"
   }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-User-Consent-For-Applications"
    reference_id         = "Deny-User-Consent-For-Applications"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-Users-Can-Register-Applications"
    reference_id         = "Deny-Users-Can-Register-Applications"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-Guest-User-Access"
    reference_id         = "Deny-Guest-User-Access"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-Owners-Manage-Group-Membership-Requests"
    reference_id         = "Deny-Owners-Manage-Group-Membership-Requests"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-Users-Create-M365-Groups"
    reference_id         = "Deny-Users-Create-M365-Groups"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Cross-Region-Restore-Enabled"
    reference_id         = "Cross-Region-Restore-Enabled"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Blob-Versioning-Enabled"
    reference_id         = "Blob-Versioning-Enabled"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Public-Network-Access-Disabled"
    reference_id         = "Public-Network-Access-Disabled"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Soft-Delete-Azure-File-Shares"
    reference_id         = "Soft-Delete-Azure-File-Shares"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Soft-Delete-Blobs-Enabled"
    reference_id         = "Soft-Delete-Blobs-Enabled"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Force-Virtual-Network-Encryption"
    reference_id         = "Force-Virtual-Network-Encryption"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/enforce-ddos-protection-on-vnet"
    reference_id         = "enforce-ddos-protection-on-vnet"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-Storage-Container-Anonymous-Access"
    reference_id         = "Deny-Storage-Container-Anonymous-Access"
  }
policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Deny-KeyVault-Public-Network-Access"
    reference_id         = "Deny-KeyVault-Public-Network-Access"
  }


  #Additional parameters required for below Azure Definitions
  /*
  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/DenyAction-DeleteResources"
    reference_id         = "DenyAction-DeleteResources"
  }
  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Management/managementGroups/IMS-Root/providers/Microsoft.Authorization/policyDefinitions/Enforce-Storage-Encryption"
    reference_id         = "Enforce-Storage-Encryption"
  }
  */
}