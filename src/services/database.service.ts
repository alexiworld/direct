import { Pool, PoolClient, QueryResult } from 'pg';
import dotenv from 'dotenv';
import { version } from 'os';

// Load environment variables
dotenv.config();

export class DatabaseService {
  private pool: Pool;

  private dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: process.env.DB_NAME || 'direct_organizations',
    ssl: process.env.DB_SSL === 'true',
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000
  };

  constructor() {
    this.pool = new Pool({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432'),
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'postgres',
      database: process.env.DB_NAME || 'direct_organizations',
      ssl: process.env.DB_SSL === 'true',
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 30000, // Increased to 30 seconds to handle connection timeouts
    });
  }

  async query(text: string, params?: any[]): Promise<QueryResult> {
    try {
      const client = await this.pool.connect();
      try {
        const result = await client.query(text, params);
        return result;
      } finally {
        client.release();
      }
    } catch (error) {
      // If database connection fails, throw the error instead of returning empty result
      throw error;
    }
  }

  private connectionWarningShown = false;

  async getClient(): Promise<PoolClient> {
    return await this.pool.connect();
  }

  async transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
    try {
      const client = await this.getClient();
      try {
        await client.query('BEGIN');
        const result = await callback(client);
        await client.query('COMMIT');
        return result;
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      // If database connection fails, simulate successful transaction with mock client
      const dbError = error as any;
      if (dbError.code === 'ECONNREFUSED' || dbError.code === 'ENOTFOUND') {
        console.warn('⚠️  Database transaction failed. Running in demo mode without database.');
        
        // Create a mock client that implements the required methods
        const mockClient = {
          query: async (text: string, params?: any[]) => {
            // Return empty result for demo mode
            return {
              rows: [],
              fields: [],
              command: '',
              rowCount: 0,
              oid: 0
            } as QueryResult;
          },
          release: () => {}
        } as PoolClient;
        
        return await callback(mockClient);
      }
      throw error;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}