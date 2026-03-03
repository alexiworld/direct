#!/usr/bin/env node

/**
 * Database Connection Test Script
 * 
 * This script tests the PostgreSQL connection using the configuration from .env
 * Run this script to verify your database setup before starting the application.
 * 
 * Usage: node test-db-connection.js
 */

require('dotenv').config();

const { Pool } = require('pg');

// Database configuration from environment variables
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: process.env.DB_NAME || 'direct_organizations',
  ssl: process.env.DB_SSL === 'true',
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000
};

async function testDatabaseConnection() {
  console.log('🔍 Testing PostgreSQL connection...\n');
  
  // Display connection info (without password)
  console.log('📊 Connection Configuration:');
  console.log(`   Host: ${dbConfig.host}`);
  console.log(`   Port: ${dbConfig.port}`);
  console.log(`   User: ${dbConfig.user}`);
  console.log(`   Database: ${dbConfig.database}`);
  console.log(`   SSL: ${dbConfig.ssl ? 'Enabled' : 'Disabled'}`);
  console.log('');

  const pool = new Pool(dbConfig);

  try {
    // Test connection
    console.log('🔌 Attempting to connect...');
    const client = await pool.connect();
    
    // Test basic query
    console.log('✅ Connection successful!');
    console.log('🔍 Running basic queries...');
    
    // Get PostgreSQL version
    const versionResult = await client.query('SELECT version()');
    console.log(`   PostgreSQL Version: ${versionResult.rows[0].version.split(' ')[0]} ${versionResult.rows[0].version.split(' ')[1]}`);
    
    // Get current time
    const timeResult = await client.query('SELECT NOW() as current_time');
    console.log(`   Current Time: ${timeResult.rows[0].current_time}`);
    
    // Check if database exists
    const dbCheckResult = await client.query(
      'SELECT datname FROM pg_database WHERE datname = $1', 
      [dbConfig.database]
    );
    
    if (dbCheckResult.rows.length > 0) {
      console.log(`✅ Database '${dbConfig.database}' exists`);
    } else {
      console.log(`❌ Database '${dbConfig.database}' does not exist`);
      console.log('💡 You need to create the database first:');
      console.log(`   CREATE DATABASE ${dbConfig.database};`);
    }
    
    // Check if tables exist
    const tableCheckResult = await client.query(
      `SELECT table_name FROM information_schema.tables 
       WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`
    );
    
    if (tableCheckResult.rows.length > 0) {
      console.log(`✅ Found ${tableCheckResult.rows.length} tables in database:`);
      tableCheckResult.rows.forEach(row => {
        console.log(`   - ${row.table_name}`);
      });
    } else {
      console.log('⚠️  No tables found in database');
      console.log('💡 Run the migration script to create tables:');
      console.log('   node setup-database.js');
    }
    
    client.release();
    console.log('\n🎉 Database connection test completed successfully!');
    
  } catch (error) {
    console.log('❌ Database connection failed!');
    console.log(`   Error: ${error.message}`);
    
    if (error.code === 'ECONNREFUSED') {
      console.log('\n💡 Troubleshooting:');
      console.log('   - PostgreSQL service may not be running');
      console.log('   - Check if PostgreSQL is installed and started');
      console.log('   - Verify the port (default: 5432) is correct');
    } else if (error.code === '28000') {
      console.log('\n💡 Troubleshooting:');
      console.log('   - Authentication failed');
      console.log('   - Check username and password in .env file');
      console.log('   - Verify PostgreSQL authentication settings');
    } else if (error.code === '3D000') {
      console.log('\n💡 Troubleshooting:');
      console.log('   - Database does not exist');
      console.log('   - Create the database: CREATE DATABASE direct_organizations;');
    } else if (error.code === 'ENOTFOUND') {
      console.log('\n💡 Troubleshooting:');
      console.log('   - Host not found');
      console.log('   - Check DB_HOST in .env file');
      console.log('   - Ensure PostgreSQL is accessible at the specified host');
    }
    
    console.log('\n🔧 Quick fixes:');
    console.log('   1. Start PostgreSQL service');
    console.log('   2. Verify .env configuration');
    console.log('   3. Create database if needed');
    console.log('   4. Run migrations to create tables');
    
  } finally {
    await pool.end();
  }
}

// Run the test
testDatabaseConnection().catch(console.error);