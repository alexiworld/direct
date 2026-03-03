import { PoolClient, QueryResult } from 'pg';
export declare class DatabaseService {
    private pool;
    private dbConfig;
    constructor();
    query(text: string, params?: any[]): Promise<QueryResult>;
    private connectionWarningShown;
    getClient(): Promise<PoolClient>;
    transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T>;
    close(): Promise<void>;
}
//# sourceMappingURL=database.service.d.ts.map