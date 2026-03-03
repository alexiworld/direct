import { SetMetadata } from '@nestjs/common';

export const HAS_PERMISSION_KEY = 'hasPermission';

export const HasPermission = (permission: string) => SetMetadata(HAS_PERMISSION_KEY, permission);
