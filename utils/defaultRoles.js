// ========================================
// ROLES Y PERMISOS POR DEFECTO
// A01: Pérdida de Control de Acceso
// ========================================

const PERMISSIONS = {
  // Inventario
  'inventory.view': 'Ver inventario',
  'inventory.create': 'Crear productos',
  'inventory.update': 'Actualizar productos',
  'inventory.delete': 'Eliminar productos',
  
  // Usuarios
  'users.view': 'Ver usuarios',
  'users.create': 'Crear usuarios',
  'users.update': 'Actualizar usuarios',
  'users.delete': 'Eliminar usuarios',
  
  // Roles
  'roles.view': 'Ver roles',
  'roles.create': 'Crear roles',
  'roles.update': 'Actualizar roles',
  'roles.delete': 'Eliminar roles',
  
  // Reportes
  'reports.view': 'Ver reportes',
  'reports.export': 'Exportar reportes',
  
  // Configuración
  'settings.view': 'Ver configuración',
  'settings.update': 'Modificar configuración'
};

const DEFAULT_ROLES = {
  'ADMIN': {
    name: 'Administrador',
    description: 'Control total del sistema',
    permissions: Object.keys(PERMISSIONS)
  },
  'MANAGER': {
    name: 'Gerente',
    description: 'Gestión de inventario y reportes',
    permissions: [
      'inventory.view', 'inventory.create', 'inventory.update',
      'reports.view', 'reports.export',
      'users.view'
    ]
  },
  'USER': {
    name: 'Usuario',
    description: 'Solo consulta y creación de inventario',
    permissions: ['inventory.view', 'inventory.create']
  },
  'VIEWER': {
    name: 'Visualizador',
    description: 'Solo lectura',
    permissions: ['inventory.view', 'reports.view']
  }
};

module.exports = {
  PERMISSIONS,
  DEFAULT_ROLES
};
