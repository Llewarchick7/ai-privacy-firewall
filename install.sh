#!/bin/bash

# AI Privacy Firewall Installation Script
# This script sets up the AI Privacy Firewall backend and dependencies

set -e

echo "🛡️ AI Privacy Firewall Installation Script"
echo "==========================================="

# Check if Python 3.10+ is installed
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
required_version="3.10"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Error: Python 3.10 or higher is required. Found: $python_version"
    exit 1
fi

echo "✅ Python version check passed: $python_version"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📚 Installing Python dependencies..."
pip install -r requirements.txt

# Check if PostgreSQL is installed
if command -v psql >/dev/null 2>&1; then
    echo "✅ PostgreSQL found"
    
    # Ask if user wants to create database
    read -p "🗄️ Do you want to create a new database? (y/n): " create_db
    if [ "$create_db" = "y" ] || [ "$create_db" = "Y" ]; then
        read -p "📝 Enter database name [ai_privacy_firewall]: " db_name
        db_name=${db_name:-ai_privacy_firewall}
        
        read -p "📝 Enter database user [postgres]: " db_user
        db_user=${db_user:-postgres}
        
        echo "🔨 Creating database..."
        createdb -U "$db_user" "$db_name" || echo "⚠️ Database might already exist"
        
        # Update .env file
        if [ ! -f .env ]; then
            cp .env.example .env
        fi
        
        # Update database URL in .env
        sed -i "s|DATABASE_URL=.*|DATABASE_URL=postgresql://$db_user@localhost/$db_name|" .env
        echo "✅ Database configuration updated in .env"
    fi
else
    echo "⚠️ PostgreSQL not found. Please install PostgreSQL:"
    echo "   - Ubuntu/Debian: sudo apt install postgresql postgresql-contrib"
    echo "   - macOS: brew install postgresql"
    echo "   - Windows: Download from https://www.postgresql.org/download/"
fi

# Set up .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "⚠️ Please edit .env file with your database credentials and API keys"
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p backend/models
mkdir -p data/blocklists
mkdir -p logs
mkdir -p models

# Download sample blocklists
echo "📋 Downloading sample blocklists..."
curl -o data/blocklists/malware.txt "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" 2>/dev/null || echo "⚠️ Could not download blocklist"

# Test the installation
echo "🧪 Testing installation..."
cd backend

# Test database connection
python3 -c "
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine

load_dotenv()
DATABASE_URL = os.getenv('DATABASE_URL')

try:
    engine = create_engine(DATABASE_URL)
    connection = engine.connect()
    connection.close()
    print('✅ Database connection successful')
except Exception as e:
    print(f'❌ Database connection failed: {e}')
    print('Please check your DATABASE_URL in the .env file')
"

cd ..

# Create systemd service file for device (if on Linux)
if [ -f /etc/systemd/system ] && [ -d device ]; then
    echo "⚙️ Creating systemd service file..."
    sudo tee /etc/systemd/system/dns-firewall.service > /dev/null <<EOF
[Unit]
Description=AI Privacy Firewall Device Monitor
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=$(pwd)/device
ExecStart=$(pwd)/venv/bin/python dns_monitor.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    echo "✅ Systemd service created. Enable with: sudo systemctl enable dns-firewall"
fi

echo ""
echo "🎉 Installation completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Edit .env file with your configuration"
echo "2. Start the backend server:"
echo "   cd backend && python -m uvicorn main:app --reload"
echo "3. Open the dashboard: dashboard/index.html"
echo "4. For device setup, see device/README.md"
echo ""
echo "📖 Full documentation: README.md"
echo "🆘 Support: https://github.com/your-repo/ai-privacy-firewall/issues"
