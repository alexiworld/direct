# PostgreSQL Setup Guide

This guide will help you set up PostgreSQL for the Direct Organization Management System.

## Option 1: Install PostgreSQL Locally

### Windows Installation

1. **Download PostgreSQL**
   - Go to https://www.postgresql.org/download/windows/
   - Download the installer for your Windows version
   - Run the installer

2. **Installation Steps**
   - Choose components: Select "PostgreSQL Server", "pgAdmin 4", and "Command Line Tools"
   - Choose installation directory: Default is usually `C:\Program Files\PostgreSQL\15\`
   - Choose data directory: Default is usually `C:\Program Files\PostgreSQL\15\data\`
   - Set password: Remember this password (you'll need it for DB_PASSWORD in .env)
   - Port: Default is 5432 (keep this unless you have conflicts)
   - Locale: Default locale is fine

3. **Start PostgreSQL Service**
   ```bash
   # Open Command Prompt as Administrator
   net start postgresql-x64-15
   ```

4. **Verify Installation**
   ```bash
   # Test connection
   psql -U postgres -h localhost -p 5432
   ```

### macOS Installation

1. **Using Homebrew**
   ```bash
   # Install PostgreSQL
   brew install postgresql
   
   # Start PostgreSQL service
   brew services start postgresql
   
   # Verify installation
   psql postgres
   ```

### Linux Installation (Ubuntu/Debian)

1. **Install PostgreSQL**
   ```bash
   # Update package list
   sudo apt update
   
   # Install PostgreSQL and contrib package
   sudo apt install postgresql postgresql-contrib
   
   # Start PostgreSQL service
   sudo systemctl start postgresql.service
   
   # Enable auto-start on boot
   sudo systemctl enable postgresql.service
   ```

## Option 2: Use Docker (Recommended)

### Docker Installation

1. **Install Docker Desktop**
   - Download from https://www.docker.com/products/docker-desktop/
   - Follow installation instructions for your OS

2. **Run PostgreSQL with Docker**
   ```bash
   # Create and run PostgreSQL container
   docker run --name direct-postgres \
     -e POSTGRES_DB=direct_organizations \
     -e POSTGRES_USER=postgres \
     -e POSTGRES_PASSWORD=postgres \
     -p 5432:5432 \
     -d postgres:15-alpine
   ```

3. **Verify Docker Container**
   ```bash
   # Check if container is running
   docker ps
   
   # View logs
   docker logs direct-postgres
   ```

## Database Setup

### Create Database and Run Migrations

1. **Connect to PostgreSQL**
   ```bash
   # Using psql command line
   psql -U postgres -h localhost -p 5432
   
   # Or using Docker
   docker exec -it direct-postgres psql -U postgres
   ```

2. **Create Database**
   ```sql
   -- Create the database
   CREATE DATABASE direct_organizations;
   
   -- Verify database creation
   \l
   
   -- Connect to the database
   \c direct_organizations
   ```

3. **Run Migrations**
   ```bash
   # Navigate to project directory
   cd /path/to/direct
   
   # Run the setup script
   node setup-database.js
   
   # Or run migrations manually
   npm run migrate
   ```

## Environment Configuration

Make sure your `.env` file has the correct PostgreSQL settings:

```env
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=direct_organizations
DB_SSL=false
```

## Troubleshooting

### Common Issues

1. **Port 5432 Already in Use**
   ```bash
   # Check what's using port 5432
   lsof -i :5432
   
   # Stop existing PostgreSQL
   sudo systemctl stop postgresql
   # or
   net stop postgresql-x64-15
   ```

2. **Connection Refused**
   - Ensure PostgreSQL service is running
   - Check firewall settings
   - Verify port configuration

3. **Authentication Failed**
   - Check username/password in .env
   - Verify PostgreSQL authentication method in pg_hba.conf

### Test Database Connection

Create a simple test script:

```javascript
// test-db.js
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: process.env.DB_NAME || 'direct_organizations',
  ssl: process.env.DB_SSL === 'true'
});

async function testConnection() {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT NOW()');
    console.log('✅ Database connection successful!');
    console.log('Current time:', result.rows[0].now);
    client.release();
  } catch (err) {
    console.error('❌ Database connection failed:', err.message);
  } finally {
    await pool.end();
  }
}

testConnection();
```

Run the test:
```bash
node test-db.js
```

## Docker Compose Setup (Alternative)

Create a `docker-compose.yml` file:

```yaml
version: '3.8'
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: direct_organizations
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  postgres_data:
```

Run with Docker Compose:
```bash
docker-compose up -d
```

## Next Steps

Once PostgreSQL is running:

1. **Build the application**
   ```bash
   npm run build
   ```

2. **Start the server**
   ```bash
   ./start.sh
   ```

3. **Test the atomic organization setup**
   ```bash
   curl -X POST http://localhost:3000/api/organizations/setup \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Acme Corporation",
       "description": "Global technology company",
       "status": "active",
       "metadata": {
         "industry": "Technology",
         "size": "Enterprise"
       },
       "powerAdmin": {
         "firstName": "John",
         "lastName": "Doe",
         "email": "john.doe@acme.com",
         "phone": "+1-555-0123",
         "metadata": {
           "employeeId": "PA-001",
           "role": "Power Admin"
         }
       },
       "rootOU": {
         "name": "Headquarters",
         "description": "Main organization unit",
         "metadata": {
           "location": "San Francisco",
           "budget": 5000000
         }
       }
     }'
   ```

This should now work with a real PostgreSQL database instead of mock data!