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
exports.OrganizationController = void 0;
const inversify_1 = require("inversify");
const data_access_service_1 = require("../services/data-access.service");
let OrganizationController = class OrganizationController {
    constructor(dataAccessService) {
        this.dataAccess = dataAccessService;
    }
    /**
     * Create a new organization
     */
    async createOrganization(req, res) {
        try {
            const { name, description, status, metadata } = req.body;
            if (!name) {
                res.status(400).json({ success: false, error: 'Organization name is required' });
                return;
            }
            const organization = {
                name,
                description: description || '',
                status: status || 'active',
                metadata: metadata || {}
            };
            const createdOrg = await this.dataAccess.createOrganization(organization);
            res.status(201).json({
                success: true,
                data: createdOrg
            });
        }
        catch (error) {
            if (error instanceof Error && error.message.includes('duplicate key')) {
                res.status(409).json({ success: false, error: 'Organization with this name already exists' });
            }
            else {
                console.error('Create organization error:', error);
                res.status(500).json({ success: false, error: 'Internal server error' });
            }
        }
    }
    /**
     * Get organization by ID
     */
    async getOrganization(req, res) {
        try {
            const { organizationId } = req.params;
            if (!organizationId) {
                res.status(400).json({ success: false, error: 'Organization ID is required' });
                return;
            }
            const organization = await this.dataAccess.getOrganization(organizationId);
            if (!organization) {
                res.status(404).json({ success: false, error: 'Organization not found' });
                return;
            }
            res.json({
                success: true,
                data: organization
            });
        }
        catch (error) {
            console.error('Get organization error:', error);
            res.status(500).json({ success: false, error: 'Internal server error' });
        }
    }
    /**
     * Update organization
     */
    async updateOrganization(req, res) {
        try {
            const { organizationId } = req.params;
            const { name, description, status, metadata } = req.body;
            if (!organizationId) {
                res.status(400).json({ success: false, error: 'Organization ID is required' });
                return;
            }
            const updates = {};
            if (name !== undefined)
                updates.name = name;
            if (description !== undefined)
                updates.description = description;
            if (status !== undefined)
                updates.status = status;
            if (metadata !== undefined)
                updates.metadata = metadata;
            const updatedOrg = await this.dataAccess.updateOrganization(organizationId, updates);
            if (!updatedOrg) {
                res.status(404).json({ success: false, error: 'Organization not found' });
                return;
            }
            res.json({
                success: true,
                data: updatedOrg
            });
        }
        catch (error) {
            if (error instanceof Error && error.message.includes('duplicate key')) {
                res.status(409).json({ success: false, error: 'Organization with this name already exists' });
            }
            else {
                console.error('Update organization error:', error);
                res.status(500).json({ success: false, error: 'Internal server error' });
            }
        }
    }
    /**
     * List organizations with pagination
     */
    async listOrganizations(req, res) {
        try {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const offset = (page - 1) * limit;
            const result = await this.dataAccess.listOrganizations(limit, offset);
            res.json({
                success: true,
                data: {
                    organizations: result.organizations,
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
            console.error('List organizations error:', error);
            res.status(500).json({ success: false, error: 'Internal server error' });
        }
    }
};
exports.OrganizationController = OrganizationController;
exports.OrganizationController = OrganizationController = __decorate([
    (0, inversify_1.injectable)(),
    __param(0, (0, inversify_1.inject)('DataAccessService')),
    __metadata("design:paramtypes", [data_access_service_1.DataAccessService])
], OrganizationController);
//# sourceMappingURL=organization.controller.js.map