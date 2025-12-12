#!/bin/bash
set -euo pipefail

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "========================================="
echo "      ADBasher Installer v2.0            "
echo "========================================="

# System Update
echo "[*] Updating system packages..."
apt-get update -qq

# Install Dependencies
echo "[*] Installing system dependencies..."
DEPS=(
    grc
    crackmapexec
    python3-dev
    python3-pip
    libsasl2-dev
    libldap2-dev
    libssl-dev
    curl
    gnupg
    apt-transport-https
    git
)
apt-get install -y --no-install-recommends "${DEPS[@]}"

# Install Python Requirements
echo "[*] Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
else
    echo "[!] requirements.txt not found!"
fi

# Install GitAuto dependencies
echo "[*] Installing GitAuto dependencies..."
pip3 install GitPython PyYAML rich

# Initialize Submodules
echo "[*] Initializing git submodules..."
# We assume the user might not be in a git repo if they just downloaded the folder,
# but if they are, we ensure submodules are pulled.
if [ -d ".git" ]; then
    git submodule update --init --recursive
else
    echo "[!] Not a git repository, skipping submodule update."
fi

# Specific Submodule Install Steps (if any needed beyond python deps)
echo "[*] Configuring submodules..."
if [ -d "3 nopass/spray/sprayhound" ]; then
    echo " -> Configuring SprayHound..."
    pushd "3 nopass/spray/sprayhound" >/dev/null
    if [ -f "setup.py" ]; then
        python3 setup.py install
    fi
    popd >/dev/null
fi

# Install PowerShell
if ! command -v pwsh &> /dev/null; then
    echo "[*] Installing PowerShell..."
    # Import the public repository GPG keys
    curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
    # Register the Microsoft Product feed
    sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-bullseye-prod bullseye main" > /etc/apt/sources.list.d/microsoft.list'
    apt-get update -qq && apt-get install -y powershell
    # Install WindowsCompatibility module
    pwsh -c "Install-Module -Name WindowsCompatibility -Force"
else
    echo "[*] PowerShell already installed."
fi

# Permissions
echo "[*] Setting permissions..."
chmod +x ./**/*.sh 2>/dev/null || true
chmod +x scripts/gitauto.py scripts/gitauto-cli.sh scripts/gitauto-cron.sh 2>/dev/null || true

echo "========================================="
echo "      Installation Complete!             "
echo "========================================="