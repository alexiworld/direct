import { Request, Response } from 'express';
import { DataAccessService } from '../services/data-access.service';
export declare class UserController {
    private dataAccess;
    constructor(dataAccessService: DataAccessService);
    /**
     * Create a new user
     */
    createUser(req: Request, res: Response): Promise<void>;
    /**
     * Get user by ID
     */
    getUser(req: Request, res: Response): Promise<void>;
    /**
     * Update user
     */
    updateUser(req: Request, res: Response): Promise<void>;
    /**
     * List users
     */
    listUsers(req: Request, res: Response): Promise<void>;
    /**
     * Move user to organization unit
     */
    moveUserToOU(req: Request, res: Response): Promise<void>;
    /**
     * Remove user from organization
     */
    removeUserFromOrganization(req: Request, res: Response): Promise<void>;
    private createUserInDB;
    private getUserFromDB;
    private updateUserInDB;
    private listUsersFromDB;
    private moveUserToOUInDB;
    private removeUserFromOrganizationInDB;
    private createMockUser;
    private getMockUser;
    private updateMockUser;
    private listMockUsers;
    private moveMockUserToOU;
    private removeMockUserFromOrganization;
    private generateUUID;
}
//# sourceMappingURL=user.controller.d.ts.map