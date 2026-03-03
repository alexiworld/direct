import { Request, Response } from 'express';
import { injectable, inject } from 'inversify';
import { DatabaseService } from '../services/database.service';
import { DataAccessService } from '../services/data-access.service';
import { UUID, Organization, ValidationError } from '../types';

@injectable()
export class OrganizationController {
  private dataAccess: DataAccessService;

  constructor(
    @inject('DataAccessService') dataAccessService: DataAccessService
  ) {
    this.dataAccess = dataAccessService;
  }

  /**
   * Create a new organization
   */
  async createOrganization(req: Request, res: Response): Promise<void> {
    try {
      const { name, description, status, metadata } = req.body;

      if (!name) {
        res.status(400).json({ success: false, error: 'Organization name is required' });
        return;
      }

      const organization: Omit<Organization, 'id' | 'createdAt' | 'updatedAt'> = {
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
    } catch (error) {
      if (error instanceof Error && error.message.includes('duplicate key')) {
        res.status(409).json({ success: false, error: 'Organization with this name already exists' });
      } else {
        console.error('Create organization error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
      }
    }
  }

  /**
   * Get organization by ID
   */
  async getOrganization(req: Request, res: Response): Promise<void> {
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
    } catch (error) {
      console.error('Get organization error:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }

  /**
   * Update organization
   */
  async updateOrganization(req: Request, res: Response): Promise<void> {
    try {
      const { organizationId } = req.params;
      const { name, description, status, metadata } = req.body;

      if (!organizationId) {
        res.status(400).json({ success: false, error: 'Organization ID is required' });
        return;
      }

      const updates: Partial<Organization> = {};
      if (name !== undefined) updates.name = name;
      if (description !== undefined) updates.description = description;
      if (status !== undefined) updates.status = status;
      if (metadata !== undefined) updates.metadata = metadata;

      const updatedOrg = await this.dataAccess.updateOrganization(organizationId, updates);

      if (!updatedOrg) {
        res.status(404).json({ success: false, error: 'Organization not found' });
        return;
      }

      res.json({
        success: true,
        data: updatedOrg
      });
    } catch (error) {
      if (error instanceof Error && error.message.includes('duplicate key')) {
        res.status(409).json({ success: false, error: 'Organization with this name already exists' });
      } else {
        console.error('Update organization error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
      }
    }
  }

  /**
   * List organizations with pagination
   */
  async listOrganizations(req: Request, res: Response): Promise<void> {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
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
    } catch (error) {
      console.error('List organizations error:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
}