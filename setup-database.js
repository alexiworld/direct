const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

async function setupDatabase() {
  console.log('🚀 Setting up Direct Organization Management System Database...');
  
  // Database connection configuration
  const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432'),
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: 'postgres', // Connect to default database first
    ssl: process.env.DB_SSL === 'true'
  };

  const pool = new Pool(dbConfig);

  try {
    // Check if database exists
    console.log('Checking if database exists...');
    const dbExistsResult = await pool.query(
      "SELECT 1 FROM pg_database WHERE datname = $1",
      [process.env.DB_NAME || 'direct_organizations']
    );

    if (dbExistsResult.rows.length === 0) {
      console.log('Creating database...');
      await pool.query(`CREATE DATABASE ${process.env.DB_NAME || 'direct_organizations'}`);
      console.log('✅ Database created successfully');
    } else {
      console.log('✅ Database already exists');
    }

    // Close connection to default database
    await pool.end();

    // Connect to the new database
    const appDbConfig = {
      ...dbConfig,
      database: process.env.DB_NAME || 'direct_organizations'
    };

    const appPool = new Pool(appDbConfig);

    // Read and execute migration files
    const migrationsDir = path.join(__dirname, 'database', 'migrations');
    const migrationFiles = fs.readdirSync(migrationsDir).filter(file => file.endsWith('.sql')).sort();

    console.log(`Found ${migrationFiles.length} migration files`);

    for (const file of migrationFiles) {
      console.log(`Executing migration: ${file}`);
      const migrationPath = path.join(migrationsDir, file);
      const migrationSQL = fs.readFileSync(migrationPath, 'utf8');
      
      try {
        await appPool.query(migrationSQL);
        console.log(`✅ Migration ${file} executed successfully`);
      } catch (error) {
        console.error(`❌ Migration ${file} failed:`, error.message);
        throw error;
      }
    }

    // Create some sample data for testing
    console.log('Creating sample data...');
    await createSampleData(appPool);

    await appPool.end();
    console.log('✅ Database setup completed successfully');

  } catch (error) {
    console.error('❌ Database setup failed:', error.message);
    process.exit(1);
  }
}

async function createSampleData(pool) {
  // Note: Sample data is now created in the migration files to ensure proper UUID format
  // This function is kept for backward compatibility but doesn't create duplicate data
  console.log('✅ Sample data already exists from migrations');
}

// Run the setup
setupDatabase();