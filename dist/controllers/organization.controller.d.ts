import { Request, Response } from 'express';
import { DataAccessService } from '../services/data-access.service';
export declare class OrganizationController {
    private dataAccess;
    constructor(dataAccessService: DataAccessService);
    /**
     * Create a new organization
     */
    createOrganization(req: Request, res: Response): Promise<void>;
    /**
     * Get organization by ID
     */
    getOrganization(req: Request, res: Response): Promise<void>;
    /**
     * Update organization
     */
    updateOrganization(req: Request, res: Response): Promise<void>;
    /**
     * List organizations with pagination
     */
    listOrganizations(req: Request, res: Response): Promise<void>;
}
//# sourceMappingURL=organization.controller.d.ts.map