#!/bin/bash
# ADBasher Web Dashboard - Setup Script
# Installs all dependencies and prepares for launch

set -e

echo "======================================"
echo "ADBasher Web Dashboard Setup"
echo "======================================"
echo ""

# Check if running from ADBasher root
if [ ! -f "core/orchestrator.py" ]; then
    echo "❌ Error: Please run this script from ADBasher root directory"
    exit 1
fi

# Check Docker
echo "📦 Checking Docker..."
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first:"
    echo "   https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose:"
    echo "   https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Option 1: Docker deployment (recommended)
echo "======================================"
echo "Deployment Options:"
echo "======================================"
echo ""
echo "1. Docker Deployment (Recommended)"
echo "   - One command to start"
echo "   - No manual dependency installation"
echo "   - Isolated environment"
echo ""
echo "2. Manual Development Setup"
echo "   - Install dependencies manually"
echo "   - Good for development"
echo "   - Requires Python 3.10+ and Node 18+"
echo ""
read -p "Choose deployment method (1 or 2): " choice

if [ "$choice" == "1" ]; then
    echo ""
    echo "🐳 Docker Deployment Selected"
    echo "======================================"
    echo ""
    echo "Building containers (this may take a few minutes)..."
    docker-compose build
    
    echo ""
    echo "✅ Setup complete!"
    echo ""
    echo "To start the dashboard:"
    echo "  docker-compose up -d"
    echo ""
    echo "To view logs:"
    echo "  docker-compose logs -f"
    echo ""
    echo "To stop the dashboard:"
    echo "  docker-compose down"
    echo ""
    echo "Dashboard will be available at:"
    echo "  → http://localhost:3000"
    echo ""
    
elif [ "$choice" == "2" ]; then
    echo ""
    echo "🔧 Manual Development Setup"
    echo "======================================"
    echo ""
    
    # Check Python
    echo "Checking Python..."
    if ! command -v python3 &> /dev/null; then
        echo "❌ Python 3 is not installed"
        exit 1
    fi
    
    python_version=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    echo "✅ Python $python_version found"
    
    # Check Node
    echo "Checking Node.js..."
    if ! command -v node &> /dev/null; then
        echo "❌ Node.js is not installed. Please install Node.js 18+:"
        echo "   https://nodejs.org/"
        exit 1
    fi
    
    node_version=$(node --version)
    echo "✅ Node $node_version found"
    
    # Install backend dependencies
    echo ""
    echo "📦 Installing backend dependencies..."
    cd web
    pip3 install -r requirements.txt
    cd ..
    
    # Install frontend dependencies
    echo ""
    echo "📦 Installing frontend dependencies..."
    cd web/frontend
    npm install
    cd ../..
    
    echo ""
    echo "✅ Setup complete!"
    echo ""
    echo "To start the backend (Terminal 1):"
    echo "  cd web && python3 app.py"
    echo ""
    echo "To start the frontend (Terminal 2):"
    echo "  cd web/frontend && npm run dev"
    echo ""
    echo "Dashboard will be available at:"
    echo "  → http://localhost:3000"
    echo ""
else
    echo "Invalid choice. Exiting."
    exit 1
fi

echo "======================================"
echo "📚 Additional Resources:"
echo "======================================"
echo ""
echo "• Quick Start: web/QUICKSTART.md"
echo "• Full Guide:  web/README.md"
echo "• API Docs:    See README for endpoints"
echo ""
echo "Happy hacking! 🎯"
