#!/usr/bin/env bash

# Variables (edit as needed)
# Storage Account in Management Subscription
RESOURCE_GROUP="ims-prd-mgmt-ne-rg-mgtfstate" # Resource group under respective subscription for Terraform state management
LOCATION="northeurope" # Azure region
STORAGE_ACCOUNT="prdmgmtmgst" # must be globally unique, 3-24 chars, lowercase/numbers only
CONTAINER="tfstate"
SUBSCRIPTION_ID ="87d1b79f-82bc-4d1e-8c6e-b20bbde0f6d6" # Management Subscription ID 
ASSIGNEE_OBJECT_ID="f2b42ea5-86bb-4af0-b100-d5624d399b21" # Object ID of the user or service principal to assign the role to
LOG_RESOURCE_GROUP="ims-prod-management-neu-rg-log-security" # Resource group where the Log Analytics workspace is located

# IPs to whitelist (GitHub Runner IPs)
IP_RULE_1="145.132.234.64/28"
IP_RULE_2="57.151.128.96/28"

# Create resource group
az group create --name "$RESOURCE_GROUP" --location "$LOCATION"


# Create storage account with guardrails and firewall enabled
az storage account create \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --sku Standard_GRS \
  --kind StorageV2 \
  --min-tls-version TLS1_2 \
  --https-only true \
  --allow-blob-public-access false

# Set default action to Deny (only allow selected networks and IPs)
az storage account update \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --default-action Deny

# Whitelist the two IP ranges
az storage account network-rule add \
  --resource-group $RESOURCE_GROUP \
  --account-name $STORAGE_ACCOUNT \
  --ip-address $IP_RULE_1

az storage account network-rule add \
  --resource-group $RESOURCE_GROUP \
  --account-name $STORAGE_ACCOUNT \
  --ip-address $IP_RULE_2

echo "Storage Account $STORAGE_ACCOUNT created with access restricted to $IP_RULE_1 and $IP_RULE_2."

  
# Get storage account key
ACCOUNT_KEY=$(az storage account keys list --resource-group "$RESOURCE_GROUP" --account-name "$STORAGE_ACCOUNT" --query '[0].value' -o tsv)

# Create private blob container
az storage container create \
  --name "$CONTAINER" \
  --account-name "$STORAGE_ACCOUNT" \
  --account-key "$ACCOUNT_KEY" \
  --public-access off

# Enable Soft Delete for Blobs and Containers
az storage blob service-properties delete-policy update --account-name "$STORAGE_ACCOUNT" --enable true --days-retained 7

echo "Storage Account: $STORAGE_ACCOUNT"
echo "Container: $CONTAINER"

# Assign Storage Blob Data Contributor role to the service principal
az role assignment create \
  --assignee $ASSIGNEE_OBJECT_ID \
  --role "Storage Blob Data Contributor" \
  --scope /subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Storage/storageAccounts/$STORAGE_ACCOUNT

# Create diagnostic settings for the storage account
az monitor diagnostic-settings create \
  --name "mgmtgrp-storage-logs" \
  --resource "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Storage/storageAccounts/$STORAGE_ACCOUNT" \
  --workspace "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$LOG_RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/ims-prod-management-neu-log-sentinel"
  --logs '[{"category": "StorageRead", "enabled": true}, {"category": "StorageWrite", "enabled": true}, {"category": "StorageDelete", "enabled": true}]' \
  --metrics '[{"category": "AllMetrics", "enabled": true}]'

# Create an alert rule for high transaction count
az monitor metrics alert create \
  --name "MgmtGrpStorageAlert" \
  --resource-group $RESOURCE_GROUP \
  --scopes /subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Storage/storageAccounts/$STORAGE_ACCOUNT \
  --condition "total transactions > 1000" \
  --description "Alert on high transaction count"

# Guardrails included:
# Storage Account firewall enabled  (--default-action Deny)
# Private container (--public-access off)
# Soft Delete enabled for blobs and containers (--enable true --days-retained 7)
# No public access (--allow-blob-public-access false)
# Disable Anonymous Read Access
# Role-based access control (RBAC) for permissions (Storage Blob Data Contributor role assigned)
# HTTPS only (--https-only true)
# TLS 1.2 enforced (--min-tls-version TLS1_2)
# Configure Blob Storage Diagnostics Logging to Log Analytics Workspace
# Enable Diagnostics Logging/Monitoring/Alerting
# Geo-redundant storage (--sku Standard_GRS)