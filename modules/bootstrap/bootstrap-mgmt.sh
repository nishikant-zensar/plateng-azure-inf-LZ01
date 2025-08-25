#!/usr/bin/env bash

# Variables (edit as needed)
# Storage Account in Management Subscription
RESOURCE_GROUP="ims-prd-mgmt-ne-rg-tfstate" # Resource group under respective subscription for Terraform state management
LOCATION="northeurope" # Azure region
STORAGE_ACCOUNT="prdmgmtlznstr" # must be globally unique, 3-24 chars, lowercase/numbers only
CONTAINER="tfstate"

# Create resource group
az group create --name "$RESOURCE_GROUP" --location "$LOCATION"

#what tags required in resource groups?

# Create storage account with guardrails
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


# Guardrails included:
# TLS 1.2 enforced (--min-tls-version TLS1_2)
# HTTPS only (--https-only true)
# Private container
# Network default action deny (--default-action Deny)
# Geo-redundant storage (--sku Standard_GRS)
