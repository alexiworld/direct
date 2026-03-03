"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HasPermission = exports.HAS_PERMISSION_KEY = void 0;
const common_1 = require("@nestjs/common");
exports.HAS_PERMISSION_KEY = 'hasPermission';
const HasPermission = (permission) => (0, common_1.SetMetadata)(exports.HAS_PERMISSION_KEY, permission);
exports.HasPermission = HasPermission;
//# sourceMappingURL=has-permission.decorator.js.map