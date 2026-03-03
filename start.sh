#!/bin/bash

# Direct Organization Management System Backend Startup Script

echo "🚀 Starting Direct Organization Management System Backend..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install npm first."
    exit 1
fi

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install dependencies"
        exit 1
    fi
fi

# Build the application
echo "🔨 Building application..."
npm run build
if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

# Start the server
echo "🌐 Starting API server..."
echo "📍 Server will be available at: http://localhost:3000"
echo "🏥 Health check: http://localhost:3000/health"
echo ""
echo "📚 Available API Endpoints:"
echo "   - GET    /health"
echo "   - POST   /api/scoped-roles/assign"
echo "   - POST   /api/scoped-roles/revoke"
echo "   - GET    /api/scoped-roles/user/:userId"
echo "   - POST   /api/permissions/check"
echo "   - GET    /api/permissions/user/:userId/scope/:scopeType/:scopeId"
echo "   - GET    /api/groups/hierarchy/user/:userId"
echo "   - POST   /api/groups/validate-operation"
echo "   - POST   /api/ous/validate-cross-operation"
echo ""
echo "Press Ctrl+C to stop the server"
echo "========================================"

npm start