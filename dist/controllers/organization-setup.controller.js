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
Object.defineProperty(exports, "__esModule", { value: true });
exports.OrganizationSetupController = void 0;
const inversify_1 = require("inversify");
const data_access_service_1 = require("../services/data-access.service");
let OrganizationSetupController = class OrganizationSetupController {
    async setupOrganization(req, res) {
        try {
            const setupData = req.body;
            // Validate required fields
            if (!setupData.name) {
                res.status(400).json({
                    success: false,
                    error: 'Organization name is required'
                });
                return;
            }
            if (!setupData.powerAdmin || !setupData.powerAdmin.firstName || !setupData.powerAdmin.lastName || !setupData.powerAdmin.email) {
                res.status(400).json({
                    success: false,
                    error: 'Power admin details are required (firstName, lastName, email)'
                });
                return;
            }
            // Execute atomic organization setup
            const result = await this.dataAccessService.setupOrganization(setupData);
            res.status(201).json({
                success: true,
                data: result
            });
        }
        catch (error) {
            console.error('Organization setup failed:', error);
            // Handle specific database constraint errors
            const dbError = error;
            if (dbError.code === '23505') { // Unique constraint violation
                res.status(409).json({
                    success: false,
                    error: 'Organization with this name or user with this email already exists'
                });
                return;
            }
            res.status(500).json({
                success: false,
                error: 'Failed to setup organization. Please try again.'
            });
        }
    }
    async getOrganizationSetupStatus(req, res) {
        try {
            const organizationId = req.params.organizationId;
            if (!organizationId) {
                res.status(400).json({
                    success: false,
                    error: 'Organization ID is required'
                });
                return;
            }
            const result = await this.dataAccessService.query(`SELECT 
           o.id as organization_id,
           o.name as organization_name,
           o.status as organization_status,
           o.created_at as organization_created_at,
           COUNT(DISTINCT ou.id) as ou_count,
           COUNT(DISTINCT u.id) as user_count,
           COUNT(DISTINCT r.id) as role_count,
           COUNT(DISTINCT ur.id) as user_role_count
         FROM organizations o
         LEFT JOIN organization_units ou ON o.id = ou.organization_id
         LEFT JOIN users u ON o.id = u.organization_id
         LEFT JOIN roles r ON o.id = r.organization_id
         LEFT JOIN user_roles ur ON r.id = ur.role_id
         WHERE o.id = $1
         GROUP BY o.id, o.name, o.status, o.created_at`, [organizationId]);
            if (result.rows.length === 0) {
                res.status(404).json({
                    success: false,
                    error: 'Organization not found'
                });
                return;
            }
            const orgData = result.rows[0];
            res.json({
                success: true,
                data: {
                    organization: {
                        id: orgData.organization_id,
                        name: orgData.organization_name,
                        status: orgData.organization_status,
                        createdAt: orgData.organization_created_at
                    },
                    setupStatus: {
                        organizationUnits: parseInt(orgData.ou_count),
                        users: parseInt(orgData.user_count),
                        roles: parseInt(orgData.role_count),
                        userRoles: parseInt(orgData.user_role_count)
                    }
                }
            });
        }
        catch (error) {
            console.error('Failed to get organization setup status:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to retrieve organization setup status'
            });
        }
    }
};
exports.OrganizationSetupController = OrganizationSetupController;
__decorate([
    (0, inversify_1.inject)('DataAccessService'),
    __metadata("design:type", data_access_service_1.DataAccessService)
], OrganizationSetupController.prototype, "dataAccessService", void 0);
exports.OrganizationSetupController = OrganizationSetupController = __decorate([
    (0, inversify_1.injectable)()
], OrganizationSetupController);
//# sourceMappingURL=organization-setup.controller.js.map