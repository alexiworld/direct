import { Request, Response } from 'express';
import { injectable, inject } from 'inversify';
import { DatabaseService } from '../services/database.service';
import { DataAccessService } from '../services/data-access.service';
import { UUID, OrganizationUnit } from '../types';

@injectable()
export class OrganizationUnitController {
  private dataAccess: DataAccessService;

  constructor(
    @inject('DataAccessService') dataAccessService: DataAccessService
  ) {
    this.dataAccess = dataAccessService;
  }

  /**
   * Create a new organization unit
   */
  async createOrganizationUnit(req: Request, res: Response): Promise<void> {
    try {
      const { organizationId, name, description, parentId, status, metadata } = req.body;

      if (!organizationId || !name) {
        res.status(400).json({ success: false, error: 'Organization ID and name are required' });
        return;
      }

      const organizationUnit: Omit<OrganizationUnit, 'id' | 'createdAt' | 'updatedAt' | 'deletedAt'> = {
        organizationId,
        parentId: parentId || null,
        name,
        description: description || null,
        address: metadata?.address || null,
        ownerId: metadata?.ownerId || null,
        hierarchyLevel: metadata?.hierarchyLevel || 1,
        path: metadata?.path || '',
        status: status || 'active'
      };

      const createdOU = await this.createOrganizationUnitInDB(organizationUnit);
      
      res.status(201).json({
        success: true,
        data: createdOU
      });
    } catch (error) {
      if (error instanceof Error && error.message.includes('duplicate key')) {
        res.status(409).json({ success: false, error: 'Organization unit with this name already exists' });
      } else {
        console.error('Create organization unit error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
      }
    }
  }

  /**
   * Get organization unit by ID
   */
  async getOrganizationUnit(req: Request, res: Response): Promise<void> {
    try {
      const { organizationId, ouId } = req.params;

      if (!organizationId || !ouId) {
        res.status(400).json({ success: false, error: 'Organization ID and OU ID are required' });
        return;
      }

      const organizationUnit = await this.getOrganizationUnitFromDB(ouId);

      if (!organizationUnit) {
        res.status(404).json({ success: false, error: 'Organization unit not found' });
        return;
      }

      res.json({
        success: true,
        data: organizationUnit
      });
    } catch (error) {
      console.error('Get organization unit error:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }

  /**
   * Update organization unit
   */
  async updateOrganizationUnit(req: Request, res: Response): Promise<void> {
    try {
      const { organizationId, ouId } = req.params;
      const { name, description, parentId, status, metadata } = req.body;

      if (!organizationId || !ouId) {
        res.status(400).json({ success: false, error: 'Organization ID and OU ID are required' });
        return;
      }

      const updates: Partial<OrganizationUnit> = {};
      if (name !== undefined) updates.name = name;
      if (description !== undefined) updates.description = description;
      if (parentId !== undefined) updates.parentId = parentId;
      if (status !== undefined) updates.status = status;
      if (metadata !== undefined) {
        updates.address = metadata.address;
        updates.ownerId = metadata.ownerId;
        updates.hierarchyLevel = metadata.hierarchyLevel;
        updates.path = metadata.path;
      }

      const updatedOU = await this.updateOrganizationUnitInDB(ouId, updates);

      if (!updatedOU) {
        res.status(404).json({ success: false, error: 'Organization unit not found' });
        return;
      }

      res.json({
        success: true,
        data: updatedOU
      });
    } catch (error) {
      if (error instanceof Error && error.message.includes('duplicate key')) {
        res.status(409).json({ success: false, error: 'Organization unit with this name already exists' });
      } else {
        console.error('Update organization unit error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
      }
    }
  }

  /**
   * List organization units
   */
  async listOrganizationUnits(req: Request, res: Response): Promise<void> {
    try {
      const { organizationId } = req.params;
      const parentId = req.query.parentId as string;
      const includeSubUnits = req.query.includeSubUnits === 'true';

      if (!organizationId) {
        res.status(400).json({ success: false, error: 'Organization ID is required' });
        return;
      }

      const result = await this.listOrganizationUnitsFromDB(organizationId, parentId, includeSubUnits);

      res.json({
        success: true,
        data: {
          units: result.units
        }
      });
    } catch (error) {
      console.error('List organization units error:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }

  /**
   * Delete organization unit
   */
  async deleteOrganizationUnit(req: Request, res: Response): Promise<void> {
    try {
      const { organizationId, ouId } = req.params;

      if (!organizationId || !ouId) {
        res.status(400).json({ success: false, error: 'Organization ID and OU ID are required' });
        return;
      }

      const deletedOU = await this.deleteOrganizationUnitFromDB(ouId);

      if (!deletedOU) {
        res.status(404).json({ success: false, error: 'Organization unit not found' });
        return;
      }

      res.json({
        success: true,
        message: 'Organization unit deleted successfully'
      });
    } catch (error) {
      console.error('Delete organization unit error:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }

  // Database methods
  private async createOrganizationUnitInDB(ou: any): Promise<any> {
    if (this.dataAccess['isDatabaseAvailable']) {
      const result = await this.dataAccess.query(
        `INSERT INTO organization_units (organization_id, parent_id, name, description, address, owner_id, hierarchy_level, path, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
         RETURNING *`,
        [ou.organizationId, ou.parentId, ou.name, ou.description, ou.address, ou.ownerId, ou.hierarchyLevel, ou.path, ou.status]
      );
      return result.rows[0];
    } else {
      return this.createMockOrganizationUnit(ou);
    }
  }

  private async getOrganizationUnitFromDB(ouId: UUID): Promise<any> {
    if (this.dataAccess['isDatabaseAvailable']) {
      const result = await this.dataAccess.query(
        'SELECT * FROM organization_units WHERE id = $1',
        [ouId]
      );
      return result.rows[0] || null;
    } else {
      return this.getMockOrganizationUnit(ouId);
    }
  }

  private async updateOrganizationUnitInDB(ouId: UUID, updates: any): Promise<any> {
    if (this.dataAccess['isDatabaseAvailable']) {
      const setClause = Object.keys(updates)
        .map((key, index) => `${key} = $${index + 2}`)
        .join(', ');
      
      const values = [ouId, ...Object.values(updates)];
      
      const result = await this.dataAccess.query(
        `UPDATE organization_units 
         SET ${setClause}, updated_at = NOW()
         WHERE id = $1
         RETURNING *`,
        values
      );
      return result.rows[0] || null;
    } else {
      return this.updateMockOrganizationUnit(ouId, updates);
    }
  }

  private async listOrganizationUnitsFromDB(organizationId: UUID, parentId?: UUID, includeSubUnits?: boolean): Promise<{ units: any[] }> {
    if (this.dataAccess['isDatabaseAvailable']) {
      let query = 'SELECT * FROM organization_units WHERE organization_id = $1';
      const params = [organizationId];
      
      if (parentId) {
        query += ' AND parent_id = $2';
        params.push(parentId);
      }
      
      query += ' ORDER BY name';
      
      const result = await this.dataAccess.query(query, params);
      return { units: result.rows };
    } else {
      return this.listMockOrganizationUnits(organizationId, parentId, includeSubUnits);
    }
  }

  private async deleteOrganizationUnitFromDB(ouId: UUID): Promise<any> {
    if (this.dataAccess['isDatabaseAvailable']) {
      const result = await this.dataAccess.query(
        `UPDATE organization_units 
         SET status = 'deleted', deleted_at = NOW()
         WHERE id = $1
         RETURNING *`,
        [ouId]
      );
      return result.rows[0] || null;
    } else {
      return this.deleteMockOrganizationUnit(ouId);
    }
  }

  // Mock methods
  private createMockOrganizationUnit(ou: any): any {
    return {
      id: this.generateUUID(),
      organizationId: ou.organizationId,
      parentId: ou.parentId,
      name: ou.name,
      description: ou.description,
      address: ou.address,
      ownerId: ou.ownerId,
      hierarchyLevel: ou.hierarchyLevel,
      path: ou.path,
      status: ou.status || 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null
    };
  }

  private getMockOrganizationUnit(ouId: UUID): any {
    return {
      id: ouId,
      organizationId: 'org-1',
      parentId: null,
      name: 'Engineering Department',
      description: 'Engineering and development team',
      address: null,
      ownerId: 'user-admin-uuid',
      hierarchyLevel: 1,
      path: ouId,
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null
    };
  }

  private updateMockOrganizationUnit(ouId: UUID, updates: any): any {
    return {
      id: ouId,
      organizationId: 'org-1',
      parentId: updates.parentId || null,
      name: updates.name || 'Engineering Department',
      description: updates.description || 'Engineering and development team',
      address: updates.address || null,
      ownerId: updates.ownerId || 'user-admin-uuid',
      hierarchyLevel: updates.hierarchyLevel || 1,
      path: updates.path || ouId,
      status: updates.status || 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null
    };
  }

  private listMockOrganizationUnits(organizationId: UUID, parentId?: UUID, includeSubUnits?: boolean): any {
    const units = [
      {
        id: 'ou-engineering-uuid',
        organizationId: 'org-1',
        parentId: null,
        name: 'Engineering Department',
        description: 'Engineering and development team',
        address: null,
        ownerId: 'user-admin-uuid',
        hierarchyLevel: 1,
        path: 'ou-engineering-uuid',
        status: 'active',
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null
      },
      {
        id: 'ou-marketing-uuid',
        organizationId: 'org-1',
        parentId: null,
        name: 'Marketing Department',
        description: 'Marketing and communications team',
        address: null,
        ownerId: 'user-admin-uuid',
        hierarchyLevel: 1,
        path: 'ou-marketing-uuid',
        status: 'active',
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null
      }
    ];
    
    return {
      units: units.filter(ou => ou.organizationId === organizationId && (!parentId || ou.parentId === parentId))
    };
  }

  private deleteMockOrganizationUnit(ouId: UUID): any {
    return {
      id: ouId,
      organizationId: 'org-1',
      parentId: null,
      name: 'Engineering Department',
      description: 'Engineering and development team',
      address: null,
      ownerId: 'user-admin-uuid',
      hierarchyLevel: 1,
      path: ouId,
      status: 'deleted',
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: new Date()
    };
  }

  private generateUUID(): UUID {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}