#!/bin/bash

##############################################
# Script Name: create_proxmox_vm_from_template.sh
#
# Description:
# This script automates the creation of a new VM in Proxmox VE
# based on a selected template or predefined configuration.
# The user can either:
# - Use a predefined configuration ("Small", "Medium", "Large").
# - Manually specify the amount of RAM, CPU cores, and disk size.
# The user can also decide whether or not to start the VM after creation.
#
# Note: Templates are created using the companion script: 
# create_proxmox_vm_templates.sh.
# This script assumes the Ubuntu 24.04 template (ID: 9401) 
# and Ubuntu 22.04 template (ID: 9201) have already been created.
#
# Predefined Configurations:
# - Small: 1 core, 1GB RAM, 32GB disk.
# - Medium: 2 cores, 2GB RAM, 32GB disk.
# - Large: 4 cores, 4GB RAM, 64GB disk.
#
# Author: Khaosx
##############################################

# Predefined configurations
TEMPLATE_ID=9401
declare -A CONFIGS
CONFIGS["Small"]="1 1024 32"
CONFIGS["Medium"]="2 2048 32"
CONFIGS["Large"]="4 4096 64"

# Prompt user for input
echo "Select a predefined configuration or set custom values:"
echo "1) Small (1 core, 1GB RAM, 32GB disk)"
echo "2) Medium (2 cores, 2GB RAM, 32GB disk)"
echo "3) Large (4 cores, 4GB RAM, 64GB disk)"
echo "4) Custom configuration"
read -p "Enter your choice (1-4): " CHOICE

# Set VM configuration based on the choice
if [[ "$CHOICE" -ge 1 && "$CHOICE" -le 3 ]]; then
  CONFIG_NAME=""
  case $CHOICE in
    1) CONFIG_NAME="Small" ;;
    2) CONFIG_NAME="Medium" ;;
    3) CONFIG_NAME="Large" ;;
  esac
  CONFIG=(${CONFIGS[$CONFIG_NAME]})
  VM_CORES=${CONFIG[0]}
  VM_RAM=${CONFIG[1]}
  VM_DISK_SIZE=${CONFIG[2]}
  echo "You selected the $CONFIG_NAME configuration."
else
  read -p "Enter the amount of RAM for the VM (in MB, e.g., 2048): " VM_RAM
  read -p "Enter the number of CPU cores for the VM (e.g., 2): " VM_CORES
  read -p "Enter the size of the hard disk for the VM (in GB, e.g., 50): " VM_DISK_SIZE
fi

# Prompt for additional details
read -p "Enter a unique VM ID for the new VM (e.g., 9501): " NEW_VM_ID
read -p "Enter a name for the new VM (e.g., MyUbuntuVM): " VM_NAME

# Clone the template
echo "Cloning template $TEMPLATE_ID to create VM $NEW_VM_ID..."
qm clone $TEMPLATE_ID $NEW_VM_ID --name $VM_NAME --full

# Configure the new VM
echo "Configuring VM $NEW_VM_ID..."
qm set $NEW_VM_ID --memory $VM_RAM
qm set $NEW_VM_ID --cores $VM_CORES
qm set $NEW_VM_ID --scsihw virtio-scsi-pci
qm set $NEW_VM_ID --scsi0 vm-disks:${NEW_VM_ID}-disk-0,size=${VM_DISK_SIZE}G
qm set $NEW_VM_ID --net0 virtio,bridge=vmbr0

# Prompt to start the VM
read -p "Would you like to start the VM now? (yes/no): " START_VM
if [[ "$START_VM" =~ ^([yY][eE][sS]|[yY])$ ]]; then
  echo "Starting VM $NEW_VM_ID..."
  qm start $NEW_VM_ID
  echo "VM $NEW_VM_ID ($VM_NAME) has been created and started successfully!"
else
  echo "VM $NEW_VM_ID ($VM_NAME) has been created. You can start it manually when ready."
fi

echo "Script completed."