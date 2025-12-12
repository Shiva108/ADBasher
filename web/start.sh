#!/bin/bash
# Quick launcher for ADBasher Web Dashboard

set -e

echo "🚀 Starting ADBasher Web Dashboard..."
echo ""

# Check if Docker Compose is available
if command -v docker-compose &> /dev/null; then
    echo "Using Docker Compose..."
    docker-compose up -d
    
    echo ""
    echo "✅ Dashboard started successfully!"
    echo ""
    echo "📊 Dashboard:  http://localhost:3000"
    echo "🔧 Backend:    http://localhost:5000"
    echo ""
    echo "View logs with: docker-compose logs -f"
    echo "Stop with:      docker-compose down"
    echo ""
else
    echo "❌ Docker Compose not found."
    echo ""
    echo "Please either:"
    echo "  1. Install Docker Compose"
    echo "  2. Run manually:"
    echo "     Terminal 1: cd web && python3 app.py"
    echo "     Terminal 2: cd web/frontend && npm run dev"
    exit 1
fi
