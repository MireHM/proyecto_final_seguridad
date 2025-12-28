const express = require('express');
const { body, validationResult } = require('express-validator');
const { db, logAudit } = require('../utils/database');
const { authenticateToken } = require('../utils/auth');
const logger = require('../utils/logger');

const router = express.Router();

// ========================================
// MATRIZ DE ROLES Y PERMISOS
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
    description: 'Solo consulta de inventario',
    permissions: ['inventory.view']
  },
  'VIEWER': {
    name: 'Visualizador',
    description: 'Solo lectura',
    permissions: ['inventory.view', 'reports.view']
  }
};

// ========================================
// MIDDLEWARE DE AUTORIZACIÓN
// ========================================

/**
 * A01: Pérdida de Control de Acceso
 * Middleware para verificar permisos específicos
 */
function authorize(requiredPermissions) {
  return async (req, res, next) => {
    try {
      const userId = req.user.id;
      
      // Obtener rol del usuario
      const user = await new Promise((resolve, reject) => {
        db.get('SELECT role FROM users WHERE id = ?', [userId], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });
      
      if (!user || !user.role) {
        logger.warn(`Usuario sin rol asignado: ${userId}`);
        return res.status(403).json({
          success: false,
          message: 'No tienes permisos para esta acción'
        });
      }
      
      // Obtener permisos del rol
      const role = await new Promise((resolve, reject) => {
        db.get('SELECT permissions FROM roles WHERE name = ?', [user.role], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });
      
      if (!role) {
        logger.warn(`Rol no encontrado: ${user.role}`);
        return res.status(403).json({
          success: false,
          message: 'Rol inválido'
        });
      }
      
      // Parsear permisos (están guardados como JSON)
      const userPermissions = JSON.parse(role.permissions || '[]');
      
      // Verificar si el usuario tiene todos los permisos requeridos
      const hasPermission = requiredPermissions.every(perm => 
        userPermissions.includes(perm)
      );
      
      if (!hasPermission) {
        await logAudit(
          userId,
          'ACCESS_DENIED',
          'authorization',
          null,
          `Permiso denegado: ${requiredPermissions.join(', ')}`,
          req.ip
        );
        
        logger.warn(`Acceso denegado para usuario ${userId} - Permisos requeridos: ${requiredPermissions.join(', ')}`);
        
        return res.status(403).json({
          success: false,
          message: 'No tienes permisos para esta acción',
          required: requiredPermissions,
          current: userPermissions
        });
      }
      
      // Usuario autorizado
      req.userPermissions = userPermissions;
      next();
      
    } catch (error) {
      logger.error('Error en autorización:', error);
      res.status(500).json({
        success: false,
        message: 'Error verificando permisos'
      });
    }
  };
}

// ========================================
// LISTAR TODOS LOS ROLES
// ========================================
router.get('/', authenticateToken, authorize(['roles.view']), (req, res) => {
  db.all(
    'SELECT id, name, description, permissions, is_system, active, created_at FROM roles WHERE active = 1 ORDER BY name',
    [],
    (err, roles) => {
      if (err) {
        logger.error('Error listando roles:', err);
        return res.status(500).json({
          success: false,
          message: 'Error obteniendo roles'
        });
      }
      
      // Parsear permisos
      const rolesWithPermissions = roles.map(role => ({
        ...role,
        permissions: JSON.parse(role.permissions || '[]')
      }));
      
      res.json({
        success: true,
        roles: rolesWithPermissions
      });
    }
  );
});

// ========================================
// OBTENER ROL POR ID
// ========================================
router.get('/:id', authenticateToken, authorize(['roles.view']), (req, res) => {
  const { id } = req.params;
  
  db.get(
    'SELECT id, name, description, permissions, is_system, active FROM roles WHERE id = ?',
    [id],
    (err, role) => {
      if (err) {
        logger.error('Error obteniendo rol:', err);
        return res.status(500).json({
          success: false,
          message: 'Error obteniendo rol'
        });
      }
      
      if (!role) {
        return res.status(404).json({
          success: false,
          message: 'Rol no encontrado'
        });
      }
      
      res.json({
        success: true,
        role: {
          ...role,
          permissions: JSON.parse(role.permissions || '[]')
        }
      });
    }
  );
});

// ========================================
// CREAR NUEVO ROL
// ========================================
router.post('/', [
  authenticateToken,
  authorize(['roles.create']),
  body('name').trim().notEmpty().isLength({ min: 3, max: 50 }).escape(),
  body('description').trim().isLength({ max: 200 }).escape(),
  body('permissions').isArray()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Datos inválidos',
      errors: errors.array()
    });
  }
  
  const { name, description, permissions } = req.body;
  const userId = req.user.id;
  
  // Validar que los permisos existan
  const invalidPermissions = permissions.filter(p => !PERMISSIONS[p]);
  if (invalidPermissions.length > 0) {
    return res.status(400).json({
      success: false,
      message: 'Permisos inválidos',
      invalid: invalidPermissions
    });
  }
  
  try {
    db.run(
      'INSERT INTO roles (name, description, permissions, is_system, created_by) VALUES (?, ?, ?, 0, ?)',
      [name, description, JSON.stringify(permissions), userId],
      async function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(400).json({
              success: false,
              message: 'Ya existe un rol con ese nombre'
            });
          }
          logger.error('Error creando rol:', err);
          return res.status(500).json({
            success: false,
            message: 'Error creando rol'
          });
        }
        
        const roleId = this.lastID;
        
        await logAudit(
          userId,
          'CREATE',
          'roles',
          roleId,
          `Rol creado: ${name} con ${permissions.length} permisos`,
          req.ip
        );
        
        logger.info(`Rol creado: ${name} (ID: ${roleId}) por usuario ${userId}`);
        
        res.status(201).json({
          success: true,
          message: 'Rol creado exitosamente',
          roleId: roleId
        });
      }
    );
  } catch (error) {
    logger.error('Error en creación de rol:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// ========================================
// ACTUALIZAR ROL
// ========================================
router.put('/:id', [
  authenticateToken,
  authorize(['roles.update']),
  body('name').optional().trim().isLength({ min: 3, max: 50 }).escape(),
  body('description').optional().trim().isLength({ max: 200 }).escape(),
  body('permissions').optional().isArray()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Datos inválidos',
      errors: errors.array()
    });
  }
  
  const { id } = req.params;
  const { name, description, permissions } = req.body;
  const userId = req.user.id;
  
  // Verificar que el rol existe y no es de sistema
  db.get('SELECT is_system, name FROM roles WHERE id = ?', [id], async (err, role) => {
    if (err) {
      logger.error('Error verificando rol:', err);
      return res.status(500).json({
        success: false,
        message: 'Error verificando rol'
      });
    }
    
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Rol no encontrado'
      });
    }
    
    if (role.is_system === 1) {
      return res.status(403).json({
        success: false,
        message: 'No se pueden modificar roles del sistema'
      });
    }
    
    // Validar permisos si se proporcionan
    if (permissions) {
      const invalidPermissions = permissions.filter(p => !PERMISSIONS[p]);
      if (invalidPermissions.length > 0) {
        return res.status(400).json({
          success: false,
          message: 'Permisos inválidos',
          invalid: invalidPermissions
        });
      }
    }
    
    // Construir query dinámico
    const updates = [];
    const values = [];
    
    if (name) {
      updates.push('name = ?');
      values.push(name);
    }
    if (description !== undefined) {
      updates.push('description = ?');
      values.push(description);
    }
    if (permissions) {
      updates.push('permissions = ?');
      values.push(JSON.stringify(permissions));
    }
    
    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No hay datos para actualizar'
      });
    }
    
    updates.push('updated_at = CURRENT_TIMESTAMP');
    values.push(id);
    
    db.run(
      `UPDATE roles SET ${updates.join(', ')} WHERE id = ?`,
      values,
      async function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(400).json({
              success: false,
              message: 'Ya existe un rol con ese nombre'
            });
          }
          logger.error('Error actualizando rol:', err);
          return res.status(500).json({
            success: false,
            message: 'Error actualizando rol'
          });
        }
        
        await logAudit(
          userId,
          'UPDATE',
          'roles',
          id,
          `Rol actualizado: ${name || role.name}`,
          req.ip
        );
        
        logger.info(`Rol actualizado: ${id} por usuario ${userId}`);
        
        res.json({
          success: true,
          message: 'Rol actualizado exitosamente'
        });
      }
    );
  });
});

// ========================================
// ELIMINAR ROL (SOFT DELETE)
// ========================================
router.delete('/:id', authenticateToken, authorize(['roles.delete']), async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  
  // Verificar que el rol existe y no es de sistema
  db.get('SELECT is_system, name FROM roles WHERE id = ?', [id], async (err, role) => {
    if (err) {
      logger.error('Error verificando rol:', err);
      return res.status(500).json({
        success: false,
        message: 'Error verificando rol'
      });
    }
    
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Rol no encontrado'
      });
    }
    
    if (role.is_system === 1) {
      return res.status(403).json({
        success: false,
        message: 'No se pueden eliminar roles del sistema'
      });
    }
    
    // Verificar si hay usuarios con este rol
    db.get('SELECT COUNT(*) as count FROM users WHERE role = ?', [role.name], (err, result) => {
      if (err) {
        logger.error('Error verificando usuarios:', err);
        return res.status(500).json({
          success: false,
          message: 'Error verificando usuarios'
        });
      }
      
      if (result.count > 0) {
        return res.status(400).json({
          success: false,
          message: `No se puede eliminar el rol. ${result.count} usuario(s) lo tienen asignado`,
          usersCount: result.count
        });
      }
      
      // Soft delete - marcar como inactivo
      db.run(
        'UPDATE roles SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [id],
        async function(err) {
          if (err) {
            logger.error('Error eliminando rol:', err);
            return res.status(500).json({
              success: false,
              message: 'Error eliminando rol'
            });
          }
          
          await logAudit(
            userId,
            'DELETE',
            'roles',
            id,
            `Rol eliminado: ${role.name}`,
            req.ip
          );
          
          logger.info(`Rol eliminado: ${id} por usuario ${userId}`);
          
          res.json({
            success: true,
            message: 'Rol eliminado exitosamente'
          });
        }
      );
    });
  });
});

// ========================================
// ASIGNAR ROL A USUARIO
// ========================================
router.post('/:roleId/assign', [
  authenticateToken,
  authorize(['users.update']),
  body('userId').isInt().toInt()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Datos inválidos',
      errors: errors.array()
    });
  }
  
  const { roleId } = req.params;
  const { userId } = req.body;
  const adminId = req.user.id;
  
  // Verificar que el rol existe
  db.get('SELECT name, active FROM roles WHERE id = ?', [roleId], (err, role) => {
    if (err || !role) {
      return res.status(404).json({
        success: false,
        message: 'Rol no encontrado'
      });
    }
    
    if (role.active === 0) {
      return res.status(400).json({
        success: false,
        message: 'El rol está inactivo'
      });
    }
    
    // Verificar que el usuario existe
    db.get('SELECT id, username FROM users WHERE id = ?', [userId], async (err, user) => {
      if (err || !user) {
        return res.status(404).json({
          success: false,
          message: 'Usuario no encontrado'
        });
      }
      
      // Asignar rol
      db.run(
        'UPDATE users SET role = ? WHERE id = ?',
        [role.name, userId],
        async function(err) {
          if (err) {
            logger.error('Error asignando rol:', err);
            return res.status(500).json({
              success: false,
              message: 'Error asignando rol'
            });
          }
          
          await logAudit(
            adminId,
            'UPDATE',
            'users',
            userId,
            `Rol ${role.name} asignado a ${user.username}`,
            req.ip
          );
          
          logger.info(`Rol ${role.name} asignado a usuario ${userId} por ${adminId}`);
          
          res.json({
            success: true,
            message: 'Rol asignado exitosamente'
          });
        }
      );
    });
  });
});

// ========================================
// LISTAR PERMISOS DISPONIBLES
// ========================================
router.get('/permissions/available', authenticateToken, authorize(['roles.view']), (req, res) => {
  const permissionsList = Object.entries(PERMISSIONS).map(([key, description]) => ({
    key,
    description,
    category: key.split('.')[0]
  }));
  
  // Agrupar por categoría
  const grouped = permissionsList.reduce((acc, perm) => {
    if (!acc[perm.category]) {
      acc[perm.category] = [];
    }
    acc[perm.category].push(perm);
    return acc;
  }, {});
  
  res.json({
    success: true,
    permissions: grouped,
    total: permissionsList.length
  });
});

module.exports = { router, authorize, PERMISSIONS, DEFAULT_ROLES };
