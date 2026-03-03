"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserController = void 0;
const inversify_1 = require("inversify");
const data_access_service_1 = require("../services/data-access.service");
let UserController = class UserController {
    constructor(dataAccessService) {
        this.dataAccess = dataAccessService;
    }
    /**
     * Create a new user
     */
    async createUser(req, res) {
        try {
            const { organizationId, organizationUnitId, firstName, lastName, email, phone, status, metadata } = req.body;
            if (!organizationId || !firstName || !lastName || !email) {
                res.status(400).json({ success: false, error: 'Organization ID, first name, last name, and email are required' });
                return;
            }
            const user = {
                organizationId,
                organizationUnitId: organizationUnitId || null,
                firstName,
                lastName,
                email,
                phone: phone || null,
                status: status || 'pending',
                metadata: metadata || {}
            };
            const createdUser = await this.createUserInDB(user);
            res.status(201).json({
                success: true,
                data: createdUser
            });
        }
        catch (error) {
            if (error instanceof Error && error.message.includes('duplicate key')) {
                res.status(409).json({ success: false, error: 'User with this email already exists' });
            }
            else {
                console.error('Create user error:', error);
                res.status(500).json({ success: false, error: 'Internal server error' });
            }
        }
    }
    /**
     * Get user by ID
     */
    async getUser(req, res) {
        try {
            const { userId } = req.params;
            if (!userId) {
                res.status(400).json({ success: false, error: 'User ID is required' });
                return;
            }
            const user = await this.getUserFromDB(userId);
            if (!user) {
                res.status(404).json({ success: false, error: 'User not found' });
                return;
            }
            res.json({
                success: true,
                data: user
            });
        }
        catch (error) {
            console.error('Get user error:', error);
            res.status(500).json({ success: false, error: 'Internal server error' });
        }
    }
    /**
     * Update user
     */
    async updateUser(req, res) {
        try {
            const { userId } = req.params;
            const { firstName, lastName, email, phone, status, metadata } = req.body;
            if (!userId) {
                res.status(400).json({ success: false, error: 'User ID is required' });
                return;
            }
            const updates = {};
            if (firstName !== undefined)
                updates.firstName = firstName;
            if (lastName !== undefined)
                updates.lastName = lastName;
            if (email !== undefined)
                updates.email = email;
            if (phone !== undefined)
                updates.phone = phone;
            if (status !== undefined)
                updates.status = status;
            if (metadata !== undefined)
                updates.metadata = metadata;
            const updatedUser = await this.updateUserInDB(userId, updates);
            if (!updatedUser) {
                res.status(404).json({ success: false, error: 'User not found' });
                return;
            }
            res.json({
                success: true,
                data: updatedUser
            });
        }
        catch (error) {
            if (error instanceof Error && error.message.includes('duplicate key')) {
                res.status(409).json({ success: false, error: 'User with this email already exists' });
            }
            else {
                console.error('Update user error:', error);
                res.status(500).json({ success: false, error: 'Internal server error' });
            }
        }
    }
    /**
     * List users
     */
    async listUsers(req, res) {
        try {
            const { organizationId, organizationUnitId, status } = req.query;
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const offset = (page - 1) * limit;
            const result = await this.listUsersFromDB(organizationId, organizationUnitId, status, limit, offset);
            res.json({
                success: true,
                data: {
                    users: result.users,
                    pagination: {
                        page,
                        limit,
                        total: result.total,
                        totalPages: Math.ceil(result.total / limit)
                    }
                }
            });
        }
        catch (error) {
            console.error('List users error:', error);
            res.status(500).json({ success: false, error: 'Internal server error' });
        }
    }
    /**
     * Move user to organization unit
     */
    async moveUserToOU(req, res) {
        try {
            const { userId } = req.params;
            const { organizationUnitId, reason } = req.body;
            if (!userId || !organizationUnitId) {
                res.status(400).json({ success: false, error: 'User ID and organization unit ID are required' });
                return;
            }
            const movedUser = await this.moveUserToOUInDB(userId, organizationUnitId, reason);
            if (!movedUser) {
                res.status(404).json({ success: false, error: 'User not found' });
                return;
            }
            res.json({
                success: true,
                message: 'User moved to organization unit successfully',
                data: {
                    previousOrganizationUnitId: movedUser.previousOrganizationUnitId,
                    newOrganizationUnitId: movedUser.newOrganizationUnitId,
                    movedAt: movedUser.movedAt
                }
            });
        }
        catch (error) {
            console.error('Move user error:', error);
            res.status(500).json({ success: false, error: 'Internal server error' });
        }
    }
    /**
     * Remove user from organization
     */
    async removeUserFromOrganization(req, res) {
        try {
            const { userId } = req.params;
            const { reason } = req.body;
            if (!userId) {
                res.status(400).json({ success: false, error: 'User ID is required' });
                return;
            }
            const removedUser = await this.removeUserFromOrganizationInDB(userId, reason);
            if (!removedUser) {
                res.status(404).json({ success: false, error: 'User not found' });
                return;
            }
            res.json({
                success: true,
                message: 'User removed from organization successfully'
            });
        }
        catch (error) {
            console.error('Remove user error:', error);
            res.status(500).json({ success: false, error: 'Internal server error' });
        }
    }
    // Database methods
    async createUserInDB(user) {
        if (this.dataAccess['isDatabaseAvailable']) {
            const result = await this.dataAccess.query(`INSERT INTO users (organization_id, organization_unit_id, first_name, last_name, email, phone, status, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
         RETURNING *`, [user.organizationId, user.organizationUnitId, user.firstName, user.lastName, user.email, user.phone, user.status, user.metadata]);
            return result.rows[0];
        }
        else {
            return this.createMockUser(user);
        }
    }
    async getUserFromDB(userId) {
        if (this.dataAccess['isDatabaseAvailable']) {
            const result = await this.dataAccess.query('SELECT * FROM users WHERE id = $1', [userId]);
            return result.rows[0] || null;
        }
        else {
            return this.getMockUser(userId);
        }
    }
    async updateUserInDB(userId, updates) {
        if (this.dataAccess['isDatabaseAvailable']) {
            const setClause = Object.keys(updates)
                .map((key, index) => `${key} = $${index + 2}`)
                .join(', ');
            const values = [userId, ...Object.values(updates)];
            const result = await this.dataAccess.query(`UPDATE users 
         SET ${setClause}, updated_at = NOW()
         WHERE id = $1
         RETURNING *`, values);
            return result.rows[0] || null;
        }
        else {
            return this.updateMockUser(userId, updates);
        }
    }
    async listUsersFromDB(organizationId, organizationUnitId, status, limit, offset) {
        if (this.dataAccess['isDatabaseAvailable']) {
            let query = 'SELECT * FROM users WHERE 1=1';
            const params = [];
            let paramIndex = 1;
            if (organizationId) {
                query += ` AND organization_id = $${paramIndex++}`;
                params.push(organizationId);
            }
            if (organizationUnitId) {
                query += ` AND organization_unit_id = $${paramIndex++}`;
                params.push(organizationUnitId);
            }
            if (status) {
                query += ` AND status = $${paramIndex++}`;
                params.push(status);
            }
            query += ` ORDER BY created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
            params.push(limit || 10, offset || 0);
            const countQuery = 'SELECT COUNT(*) FROM users WHERE 1=1' +
                (organizationId ? ` AND organization_id = $1` : '') +
                (organizationUnitId ? ` AND organization_unit_id = ${organizationId ? '$2' : '$1'}` : '') +
                (status ? ` AND status = ${organizationId || organizationUnitId ? '$3' : organizationId ? '$2' : organizationUnitId ? '$2' : '$1'}` : '');
            const countResult = await this.dataAccess.query(countQuery, organizationId || organizationUnitId || status ? params.slice(0, -2) : []);
            const total = parseInt(countResult.rows[0].count);
            const result = await this.dataAccess.query(query, params);
            return {
                users: result.rows,
                total
            };
        }
        else {
            return this.listMockUsers(organizationId, organizationUnitId, status, limit || 10, offset || 0);
        }
    }
    async moveUserToOUInDB(userId, organizationUnitId, reason) {
        if (this.dataAccess['isDatabaseAvailable']) {
            const result = await this.dataAccess.query(`UPDATE users 
         SET organization_unit_id = $2, updated_at = NOW()
         WHERE id = $1
         RETURNING *`, [userId, organizationUnitId]);
            const user = result.rows[0];
            return {
                previousOrganizationUnitId: user.organizationUnitId,
                newOrganizationUnitId: organizationUnitId,
                movedAt: new Date()
            };
        }
        else {
            return this.moveMockUserToOU(userId, organizationUnitId, reason);
        }
    }
    async removeUserFromOrganizationInDB(userId, reason) {
        if (this.dataAccess['isDatabaseAvailable']) {
            const result = await this.dataAccess.query(`UPDATE users 
         SET status = 'deleted', deleted_at = NOW()
         WHERE id = $1
         RETURNING *`, [userId]);
            return result.rows[0] || null;
        }
        else {
            return this.removeMockUserFromOrganization(userId, reason);
        }
    }
    // Mock methods
    createMockUser(user) {
        return {
            id: this.generateUUID(),
            organizationId: user.organizationId,
            organizationUnitId: user.organizationUnitId,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            phone: user.phone,
            status: user.status || 'pending',
            lastLoginAt: null,
            failedLoginAttempts: 0,
            lockedUntil: null,
            createdAt: new Date(),
            updatedAt: new Date(),
            deletedAt: null,
            metadata: user.metadata || {}
        };
    }
    getMockUser(userId) {
        return {
            id: userId,
            organizationId: 'org-1',
            organizationUnitId: 'ou-engineering-uuid',
            firstName: 'Test',
            lastName: 'User',
            email: 'user@example.com',
            phone: '098-765-4321',
            status: 'active',
            lastLoginAt: new Date(),
            failedLoginAttempts: 0,
            lockedUntil: null,
            createdAt: new Date(),
            updatedAt: new Date(),
            deletedAt: null,
            metadata: {}
        };
    }
    updateMockUser(userId, updates) {
        return {
            id: userId,
            organizationId: 'org-1',
            organizationUnitId: updates.organizationUnitId || 'ou-engineering-uuid',
            firstName: updates.firstName || 'Test',
            lastName: updates.lastName || 'User',
            email: updates.email || 'user@example.com',
            phone: updates.phone || '098-765-4321',
            status: updates.status || 'active',
            lastLoginAt: new Date(),
            failedLoginAttempts: 0,
            lockedUntil: null,
            createdAt: new Date(),
            updatedAt: new Date(),
            deletedAt: null,
            metadata: updates.metadata || {}
        };
    }
    listMockUsers(organizationId, organizationUnitId, status, limit = 10, offset = 0) {
        const users = [
            {
                id: 'user-admin-uuid',
                organizationId: 'org-1X2',
                organizationUnitId: 'ou-engineering-uuid',
                firstName: 'Admin',
                lastName: 'User',
                email: 'admin@example.com',
                phone: '123-456-7890',
                status: 'active',
                lastLoginAt: new Date(),
                failedLoginAttempts: 0,
                lockedUntil: null,
                createdAt: new Date(),
                updatedAt: new Date(),
                deletedAt: null,
                metadata: {}
            },
            {
                id: 'user-uuid',
                organizationId: 'org-1',
                organizationUnitId: 'ou-engineering-uuid',
                firstName: 'Test',
                lastName: 'User',
                email: 'user@example.com',
                phone: '098-765-4321',
                status: 'active',
                lastLoginAt: new Date(),
                failedLoginAttempts: 0,
                lockedUntil: null,
                createdAt: new Date(),
                updatedAt: new Date(),
                deletedAt: null,
                metadata: {}
            }
        ];
        const filteredUsers = users.filter(u => (!organizationId || u.organizationId === organizationId) &&
            (!organizationUnitId || u.organizationUnitId === organizationUnitId) &&
            (!status || u.status === status));
        return {
            users: filteredUsers.slice(offset, offset + limit),
            total: filteredUsers.length
        };
    }
    moveMockUserToOU(userId, organizationUnitId, reason) {
        return {
            previousOrganizationUnitId: 'ou-engineering-uuid',
            newOrganizationUnitId: organizationUnitId,
            movedAt: new Date()
        };
    }
    removeMockUserFromOrganization(userId, reason) {
        return {
            id: userId,
            organizationId: 'org-1',
            organizationUnitId: 'ou-engineering-uuid',
            firstName: 'Test',
            lastName: 'User',
            email: 'user@example.com',
            phone: '098-765-4321',
            status: 'deleted',
            lastLoginAt: new Date(),
            failedLoginAttempts: 0,
            lockedUntil: null,
            createdAt: new Date(),
            updatedAt: new Date(),
            deletedAt: new Date(),
            metadata: {}
        };
    }
    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
};
exports.UserController = UserController;
exports.UserController = UserController = __decorate([
    (0, inversify_1.injectable)(),
    __param(0, (0, inversify_1.inject)('DataAccessService')),
    __metadata("design:paramtypes", [data_access_service_1.DataAccessService])
], UserController);
//# sourceMappingURL=user.controller.js.map