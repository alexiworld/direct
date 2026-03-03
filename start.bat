@echo off
REM Direct Organization Management System - Windows Startup Script

echo 🚀 Starting Direct Organization Management System Backend...
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Error: Node.js is not installed. Please install Node.js 18+ first.
    echo    Download from: https://nodejs.org/
    pause
    exit /b 1
)

REM Check Node.js version
for /f "tokens=2 delims=v" %%i in ('node --version') do set NODE_VERSION=%%i
for /f "tokens=1 delims=." %%i in ('echo %NODE_VERSION%') do set NODE_MAJOR=%%i

if %NODE_MAJOR% lss 18 (
    echo ❌ Error: Node.js version 18+ is required. Current version: v%NODE_VERSION%
    pause
    exit /b 1
)

echo ✅ Node.js version: v%NODE_VERSION%

REM Check if npm is installed
npm --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Error: npm is not installed. Please install npm first.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('npm --version') do set NPM_VERSION=%%i
echo ✅ npm version: %NPM_VERSION%
echo.

REM Check if .env file exists
if not exist ".env" (
    echo ⚠️  Warning: .env file not found. Using .env.example as template.
    echo    Please copy .env.example to .env and configure your environment variables.
    echo.
)

REM Install dependencies if node_modules doesn't exist
if not exist "node_modules" (
    echo 📦 Installing dependencies...
    call npm install --legacy-peer-deps
    if %errorlevel% neq 0 (
        echo ❌ Failed to install dependencies
        pause
        exit /b 1
    )
    echo ✅ Dependencies installed successfully
    echo.
)

REM Build the application
echo 🔨 Building application...
call npm run build
if %errorlevel% neq 0 (
    echo ❌ Build failed. Please check the TypeScript errors above.
    pause
    exit /b 1
)
echo ✅ Build completed successfully
echo.

REM Check if dist directory exists
if not exist "dist" (
    echo ❌ Error: dist directory not found. Build may have failed.
    pause
    exit /b 1
)

REM Start the application
echo 🚀 Starting application...
echo    Application will be available at: http://localhost:3000
echo    Press Ctrl+C to stop the server
echo.

REM Start the application
call npm start