import { Request, Response } from 'express';
import { DataAccessService } from '../services/data-access.service';
export declare class OrganizationUnitController {
    private dataAccess;
    constructor(dataAccessService: DataAccessService);
    /**
     * Create a new organization unit
     */
    createOrganizationUnit(req: Request, res: Response): Promise<void>;
    /**
     * Get organization unit by ID
     */
    getOrganizationUnit(req: Request, res: Response): Promise<void>;
    /**
     * Update organization unit
     */
    updateOrganizationUnit(req: Request, res: Response): Promise<void>;
    /**
     * List organization units
     */
    listOrganizationUnits(req: Request, res: Response): Promise<void>;
    /**
     * Delete organization unit
     */
    deleteOrganizationUnit(req: Request, res: Response): Promise<void>;
    private createOrganizationUnitInDB;
    private getOrganizationUnitFromDB;
    private updateOrganizationUnitInDB;
    private listOrganizationUnitsFromDB;
    private deleteOrganizationUnitFromDB;
    private createMockOrganizationUnit;
    private getMockOrganizationUnit;
    private updateMockOrganizationUnit;
    private listMockOrganizationUnits;
    private deleteMockOrganizationUnit;
    private generateUUID;
}
//# sourceMappingURL=organization-unit.controller.d.ts.map