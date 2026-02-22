// Core Types for Organization Management System

export type UUID = string;

export interface User {
  id: UUID;
  organizationId: UUID;
  organizationUnitId: UUID | null;
  firstName: string;
  lastName: string;
  email: string;
  phone: string | null;
  status: 'pending' | 'active' | 'suspended' | 'deleted';
  lastLoginAt: Date | null;
  failedLoginAttempts: number;
  lockedUntil: Date | null;
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date | null;
}

export interface Role {
  id: UUID;
  organizationId: UUID;
  name: string;
  description: string;
  type: 'system' | 'custom';
  isSystemRole: boolean;
  status: 'active' | 'inactive' | 'deleted';
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date | null;
  permissions?: string[];
  scopeType: ScopeType;
  scopeId: UUID | null;
}

export interface UserRole {
  id: UUID;
  userId: UUID;
  roleId: UUID;
  assignedBy: UUID;
  assignedAt: Date;
  status: 'active' | 'inactive';
  createdAt: Date;
  updatedAt: Date;
  name?: string; // Role name for convenience
  scopeType?: ScopeType; // Role scope type for convenience
  scopeId?: UUID; // Role scope ID for convenience
}

export interface PermissionContext {
  userId: UUID;
  groupId?: UUID;
  organizationUnitId?: UUID;
  targetUserId?: UUID;
  targetResourceId?: UUID;
  sourceOrganizationUnitId?: UUID;
  targetOrganizationUnitId?: UUID;
  action: string;
}

export enum ScopeType {
  ORGANIZATION = 'organization',
  GROUP = 'group',
  ORGANIZATION_UNIT = 'organization_unit'
}

export interface OrganizationUnit {
  id: UUID;
  organizationId: UUID;
  parentId: UUID | null;
  name: string;
  description: string | null;
  address: any | null;
  ownerId: UUID;
  hierarchyLevel: number;
  path: string;
  status: 'active' | 'inactive' | 'deleted';
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date | null;
}

export interface Group {
  id: UUID;
  organizationId: UUID;
  parentId: UUID | null;
  name: string;
  description: string | null;
  type: 'system' | 'custom' | 'dynamic';
  status: 'active' | 'inactive' | 'deleted';
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date | null;
}

export interface AuthenticatedUser {
  id: UUID;
  organizationId: UUID;
  email: string;
  roles: UserRoleInfo[];
  permissions: string[];
  scopePermissions: ScopedPermissionInfo[];
}

export interface UserRoleInfo {
  roleId: UUID;
  roleName: string;
  scopeType: ScopeType;
  scopeId: UUID | null;
  assignedAt: Date;
}

export interface ScopedPermissionInfo {
  permissionName: string;
  scopeType: ScopeType;
  scopeId: UUID | null;
  grantedAt: Date;
}

export interface AddUserToOURequest {
  userId: UUID;
  organizationUnitId: UUID;
  reason?: string;
}

export interface AssignmentContext {
  groupId?: UUID;
  organizationUnitId?: UUID;
  reason?: string;
}

export interface ApiResponse {
  success: boolean;
  data?: any;
  message?: string;
  errors?: string[];
}

export interface ValidationError extends Error {
  code: string;
  field?: string;
  value?: any;
}

export interface AuthorizationError extends Error {
  code: string;
  resource?: string;
  action?: string;
}

export interface ForbiddenError extends Error {
  code: string;
  message: string;
}

export interface OUAccessValidation {
  hasAccess: boolean;
  accessType: 'owner' | 'manager' | 'member' | 'none';
}
