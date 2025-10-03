#!/usr/bin/env bash

set -e

# Step 1: Create and activate a virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

echo "Activating virtual environment..."
source venv/bin/activate

# Step 2: Install required Python libraries
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install mitreattack-python pyyaml rich

# Step 3: Download ATT&CK STIX bundle
echo "Downloading MITRE ATT&CK Enterprise STIX data..."
curl -sSL https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json -o enterprise-attack.json

# Step 4: Clone Sigma repository
echo "Cloning Sigma repository..."
git clone https://github.com/SigmaHQ/sigma.git

# Step 5: Create hello world Python program
echo "Creating hello world program in lookup.py..."
echo -e '#!/usr/bin/env python3\nprint("hello world")' > lookup.py
chmod +x lookup.py

echo "Setup complete! You can now run 'python lookup.py'."
echo "You should recieve 'hello world'."
