"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DatabaseService = void 0;
const pg_1 = require("pg");
const dotenv_1 = __importDefault(require("dotenv"));
// Load environment variables
dotenv_1.default.config();
class DatabaseService {
    constructor() {
        this.dbConfig = {
            host: process.env.DB_HOST || 'localhost',
            port: process.env.DB_PORT || 5432,
            user: process.env.DB_USER || 'postgres',
            password: process.env.DB_PASSWORD || 'postgres',
            database: process.env.DB_NAME || 'direct_organizations',
            ssl: process.env.DB_SSL === 'true',
            connectionTimeoutMillis: 5000,
            idleTimeoutMillis: 30000
        };
        this.connectionWarningShown = false;
        // this.pool = new Pool({
        //   host: process.env.DB_HOST || 'localhost',
        //   port: parseInt(process.env.DB_PORT || '5432'),
        //   user: process.env.DB_USER || 'postgres',
        //   password: process.env.DB_PASSWORD || 'postgres',
        //   database: process.env.DB_NAME || 'direct_organizations',
        //   ssl: process.env.DB_SSL === 'true',
        //   max: 20,
        //   idleTimeoutMillis: 30000,
        //   connectionTimeoutMillis: 30000, // Increased to 30 seconds to handle connection timeouts
        // });
        this.pool = new pg_1.Pool({
            host: 'localhost',
            port: 5432,
            user: 'postgres',
            password: 'postgres',
            database: 'direct_organizations',
            ssl: process.env.DB_SSL === 'true',
            connectionTimeoutMillis: 5000,
            idleTimeoutMillis: 30000
        });
    }
    async query(text, params) {
        try {
            const client = await this.pool.connect();
            try {
                const result = await client.query(text, params);
                return result;
            }
            finally {
                client.release();
            }
        }
        catch (error) {
            // If database connection fails, throw the error instead of returning empty result
            throw error;
        }
    }
    async getClient() {
        return await this.pool.connect();
    }
    async transaction(callback) {
        try {
            const client = await this.getClient();
            try {
                await client.query('BEGIN');
                const result = await callback(client);
                await client.query('COMMIT');
                return result;
            }
            catch (error) {
                await client.query('ROLLBACK');
                throw error;
            }
            finally {
                client.release();
            }
        }
        catch (error) {
            // If database connection fails, simulate successful transaction with mock client
            const dbError = error;
            if (dbError.code === 'ECONNREFUSED' || dbError.code === 'ENOTFOUND') {
                console.warn('⚠️  Database transaction failed. Running in demo mode without database.');
                // Create a mock client that implements the required methods
                const mockClient = {
                    query: async (text, params) => {
                        // Return empty result for demo mode
                        return {
                            rows: [],
                            fields: [],
                            command: '',
                            rowCount: 0,
                            oid: 0
                        };
                    },
                    release: () => { }
                };
                return await callback(mockClient);
            }
            throw error;
        }
    }
    async close() {
        await this.pool.end();
    }
}
exports.DatabaseService = DatabaseService;
//# sourceMappingURL=database.service.js.map