@echo off
echo.
echo 🐘 PostgreSQL Setup Script for Windows
echo ======================================
echo.
echo This script will help you set up PostgreSQL for the Direct Organization Management System.
echo.

REM Check if PostgreSQL is already installed
echo Checking if PostgreSQL is already installed...
where psql >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo ✅ PostgreSQL is already installed!
    echo.
    echo Checking if PostgreSQL service is running...
    sc query postgresql-x64-15 >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo ✅ PostgreSQL service exists.
        sc query postgresql-x64-15 | find "RUNNING" >nul
        if %ERRORLEVEL% EQU 0 (
            echo ✅ PostgreSQL service is running!
            goto :check_connection
        ) else (
            echo ⚠️  PostgreSQL service exists but is not running.
            echo Starting PostgreSQL service...
            net start postgresql-x64-15
            if %ERRORLEVEL% EQU 0 (
                echo ✅ PostgreSQL service started successfully!
                goto :check_connection
            ) else (
                echo ❌ Failed to start PostgreSQL service.
                echo 💡 Try running this script as Administrator.
                goto :install_instructions
            )
        )
    ) else (
        echo ⚠️  PostgreSQL service not found.
        echo 💡 PostgreSQL may be installed but service not configured.
        goto :install_instructions
    )
) else (
    echo ❌ PostgreSQL is not installed.
    goto :install_instructions
)

:check_connection
echo.
echo Testing database connection...
node test-db-connection.js
goto :end

:install_instructions
echo.
echo 📥 PostgreSQL Installation Instructions:
echo =========================================
echo.
echo 1. Download PostgreSQL installer from: https://www.postgresql.org/download/windows/
echo 2. Run the installer with these settings:
echo    - Components: PostgreSQL Server, pgAdmin 4, Command Line Tools
echo    - Port: 5432 (default)
echo    - Password: postgres (or your preferred password)
echo    - Remember to set the password!
echo.
echo 3. After installation, restart this script or run:
echo    node test-db-connection.js
echo.
echo 💡 Alternative: Use Docker (recommended)
echo    1. Install Docker Desktop from: https://www.docker.com/products/docker-desktop/
echo    2. Run this command in PowerShell:
echo       docker run --name direct-postgres -e POSTGRES_DB=direct_organizations -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:15-alpine
echo    3. Then run: node test-db-connection.js
echo.

:end
echo.
echo 🎯 Next Steps:
echo =============
echo 1. Ensure PostgreSQL is running
echo 2. Run: node test-db-connection.js
echo 3. Run: node setup-database.js (to create tables)
echo 4. Run: ./start.sh (to start the application)
echo 5. Test the atomic organization setup endpoint
echo.
pause