#!/bin/bash

##############################################
# Script Name: create_proxmox_vm_templates.sh
#
# Description:
# This script automates the creation of VM templates in Proxmox VE for Ubuntu 24.04 and 22.04. 
# It performs the following tasks:
# - Prompts the user for their name, GitHub username, and password.
# - Fetches the user's public SSH key from GitHub.
# - Downloads and resizes Ubuntu cloud images.
# - Configures and optimizes VMs with SSD emulation.
# - Converts the VMs into templates.
# - Cleans up temporary files after execution.
#
# Inputs:
# - User name (used as VM user)
# - GitHub username (to fetch the public SSH key)
# - Password for VM templates
#
# Outputs:
# - Two VM templates created in Proxmox VE:
#   1. Ubuntu 24.04 Template
#   2. Ubuntu 22.04 Template
# - Cleans up temporary files upon completion.
#
# Author: Kristopher (Updated by AI Copilot)
##############################################

# Prompt for user inputs
read -p "Enter your name (to be used as the VM user): " USER_NAME
read -p "Enter your GitHub username (to fetch the public SSH key): " GITHUB_USER
read -sp "Enter password for both templates: " VM_PASSWORD
echo

# Destroy existing VMs
for VMID in 9401 9201; do
  qm destroy $VMID --purge
done

# Download and resize Ubuntu cloud images
declare -A IMAGES=( ["9401"]="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img" \
                    ["9201"]="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img" )

for VMID in "${!IMAGES[@]}"; do
  IMG_PATH="/tmp/${VMID}-server-cloudimg-amd64.img"
  curl -o $IMG_PATH ${IMAGES[$VMID]}
  qemu-img resize $IMG_PATH 32G
done

# Fetch public SSH key from GitHub
curl -o /tmp/public-ssh-key.pub https://github.com/$GITHUB_USER.keys
if [ $? -ne 0 ]; then
  echo "Error fetching SSH key for GitHub user: $GITHUB_USER"
  exit 1
fi
chmod 0754 /tmp/public-ssh-key.pub

# VM-specific configurations
declare -A NAMES=( ["9401"]="ubuntu-24.04-template" ["9201"]="ubuntu-22.04-template" )
declare -A TAGS=( ["9401"]="24.04" ["9201"]="22.04" )
declare -A DESCS=( ["9401"]="Ubuntu 24.04 Template" ["9201"]="Ubuntu 22.04 Template" )

for VMID in 9401 9201; do
  IMG_PATH="/tmp/${VMID}-server-cloudimg-amd64.img"
  TEMPLATE_NAME=${NAMES[$VMID]}
  TAG=${TAGS[$VMID]}
  DESC="${DESCS[$VMID]} created by $USER_NAME"

  # Create VM and import disk
  qm create $VMID --name $TEMPLATE_NAME --efidisk0 vm-disks:0,pre-enrolled-keys=0
  qm importdisk $VMID $IMG_PATH vm-disks

  # Configure VM
  qm set $VMID --scsihw virtio-scsi-pci --scsi0 vm-disks:vm-${VMID}-disk-1,discard=on,ssd=1
  qm set $VMID --boot order=scsi0
  qm set $VMID --scsi1 vm-disks:cloudinit
  qm set $VMID --ciuser "$USER_NAME"
  qm set $VMID --cipassword "$VM_PASSWORD"
  qm set $VMID --sshkeys /tmp/public-ssh-key.pub
  qm set $VMID --ipconfig0 ip=dhcp
  qm set $VMID --serial0 socket
  qm set $VMID --vga serial0
  qm set $VMID --agent enabled=1
  qm set $VMID --memory 1024
  qm set $VMID --balloon 0
  qm set $VMID --bios ovmf
  qm set $VMID --machine q35
  qm set $VMID --ostype l26
  qm set $VMID --cpu host
  qm set $VMID --socket 1
  qm set $VMID --cores 1
  qm set $VMID --net0 virtio,bridge=vmbr0
  qm set $VMID --tags "$TAG","template"
  qm set $VMID --description "$DESC"

  # Convert to template
  qm template $VMID
done

# Cleanup temporary files
rm -f /tmp/*-server-cloudimg-amd64.img /tmp/public-ssh-key.pub
echo "Templates for Ubuntu 24.04 and 22.04 have been created successfully."
