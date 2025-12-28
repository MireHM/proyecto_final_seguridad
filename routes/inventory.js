const express = require('express');
const { body, validationResult } = require('express-validator');
const { db, logAudit } = require('../utils/database');
const { authenticateToken } = require('../utils/auth');
const logger = require('../utils/logger');

const router = express.Router();

// Todas las rutas de inventario requieren autenticación
router.use(authenticateToken);

// ========================================
// LISTAR INVENTARIO
// ========================================
router.get('/', async (req, res) => {
  db.all(
    `SELECT i.*, u.username as created_by_username 
     FROM inventory i 
     LEFT JOIN users u ON i.created_by = u.id 
     ORDER BY i.created_at DESC`,
    [],
    async (err, items) => {
      if (err) {
        logger.error(`Error listando inventario: ${err.message}`);
        return res.status(500).json({
          success: false,
          message: 'Error obteniendo inventario'
        });
      }

      await logAudit(req.user.id, 'VIEW', 'inventory', null, 'Listado de inventario', req.ip);
      
      res.json({
        success: true,
        items
      });
    }
  );
});

// ========================================
// OBTENER UN ITEM
// ========================================
router.get('/:id', async (req, res) => {
  const { id } = req.params;

  db.get(
    `SELECT i.*, u.username as created_by_username 
     FROM inventory i 
     LEFT JOIN users u ON i.created_by = u.id 
     WHERE i.id = ?`,
    [id],
    async (err, item) => {
      if (err) {
        logger.error(`Error obteniendo item: ${err.message}`);
        return res.status(500).json({
          success: false,
          message: 'Error obteniendo item'
        });
      }

      if (!item) {
        return res.status(404).json({
          success: false,
          message: 'Item no encontrado'
        });
      }

      await logAudit(req.user.id, 'VIEW', 'inventory', id, `Item ${id} consultado`, req.ip);

      res.json({
        success: true,
        item
      });
    }
  );
});

// ========================================
// CREAR ITEM
// ========================================
// INTEGRIDAD: Validación exhaustiva de datos
router.post('/', [
  body('name').trim().notEmpty().isLength({ min: 2, max: 100 }).escape(),
  body('description').optional().trim().isLength({ max: 500 }).escape(),
  body('quantity').isInt({ min: 0 }).toInt(),
  body('price').isFloat({ min: 0 }).toFloat(),
  body('category').trim().notEmpty().isIn(['Electrónica', 'Ropa', 'Alimentos', 'Herramientas', 'Otros'])
], async (req, res) => {
  // INTEGRIDAD: Verificar errores de validación
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Datos inválidos',
      errors: errors.array()
    });
  }

  const { name, description, quantity, price, category } = req.body;
  const userId = req.user.id;

  db.run(
    `INSERT INTO inventory (name, description, quantity, price, category, created_by) 
     VALUES (?, ?, ?, ?, ?, ?)`,
    [name, description || '', quantity, price, category, userId],
    async function(err) {
      if (err) {
        logger.error(`Error creando item: ${err.message}`);
        return res.status(500).json({
          success: false,
          message: 'Error creando item'
        });
      }

      const itemId = this.lastID;
      
      // DISPONIBILIDAD: Registrar en auditoría
      await logAudit(
        userId, 
        'CREATE', 
        'inventory', 
        itemId, 
        `Item creado: ${name}`, 
        req.ip
      );

      logger.info(`Item creado: ${name} (ID: ${itemId}) por usuario ${req.user.username}`);

      res.status(201).json({
        success: true,
        message: 'Item creado exitosamente',
        itemId
      });
    }
  );
});

// ========================================
// ACTUALIZAR ITEM
// ========================================
router.put('/:id', [
  body('name').optional().trim().notEmpty().isLength({ min: 2, max: 100 }).escape(),
  body('description').optional().trim().isLength({ max: 500 }).escape(),
  body('quantity').optional().isInt({ min: 0 }).toInt(),
  body('price').optional().isFloat({ min: 0 }).toFloat(),
  body('category').optional().trim().isIn(['Electrónica', 'Ropa', 'Alimentos', 'Herramientas', 'Otros'])
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
  const updates = req.body;

  // Verificar que el item existe
  db.get('SELECT * FROM inventory WHERE id = ?', [id], async (err, item) => {
    if (err || !item) {
      return res.status(404).json({
        success: false,
        message: 'Item no encontrado'
      });
    }

    // Construir query de actualización dinámicamente
    const fields = [];
    const values = [];

    Object.keys(updates).forEach(key => {
      if (['name', 'description', 'quantity', 'price', 'category'].includes(key)) {
        fields.push(`${key} = ?`);
        values.push(updates[key]);
      }
    });

    if (fields.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No hay campos para actualizar'
      });
    }

    // Agregar updated_at
    fields.push('updated_at = CURRENT_TIMESTAMP');
    values.push(id);

    const query = `UPDATE inventory SET ${fields.join(', ')} WHERE id = ?`;

    db.run(query, values, async function(err) {
      if (err) {
        logger.error(`Error actualizando item: ${err.message}`);
        return res.status(500).json({
          success: false,
          message: 'Error actualizando item'
        });
      }

      // INTEGRIDAD + DISPONIBILIDAD: Registrar cambios en auditoría
      await logAudit(
        req.user.id,
        'UPDATE',
        'inventory',
        id,
        `Item actualizado: ${JSON.stringify(updates)}`,
        req.ip
      );

      logger.info(`Item ${id} actualizado por usuario ${req.user.username}`);

      res.json({
        success: true,
        message: 'Item actualizado exitosamente'
      });
    });
  });
});

// ========================================
// ELIMINAR ITEM
// ========================================
router.delete('/:id', async (req, res) => {
  const { id } = req.params;

  // Verificar que existe antes de eliminar
  db.get('SELECT name FROM inventory WHERE id = ?', [id], async (err, item) => {
    if (err || !item) {
      return res.status(404).json({
        success: false,
        message: 'Item no encontrado'
      });
    }

    db.run('DELETE FROM inventory WHERE id = ?', [id], async function(err) {
      if (err) {
        logger.error(`Error eliminando item: ${err.message}`);
        return res.status(500).json({
          success: false,
          message: 'Error eliminando item'
        });
      }

      // DISPONIBILIDAD: Registrar eliminación en auditoría
      await logAudit(
        req.user.id,
        'DELETE',
        'inventory',
        id,
        `Item eliminado: ${item.name}`,
        req.ip
      );

      logger.info(`Item ${id} eliminado por usuario ${req.user.username}`);

      res.json({
        success: true,
        message: 'Item eliminado exitosamente'
      });
    });
  });
});

// ========================================
// BUSCAR ITEMS
// ========================================
router.get('/search/:term', async (req, res) => {
  const { term } = req.params;
  const searchTerm = `%${term}%`;

  db.all(
    `SELECT i.*, u.username as created_by_username 
     FROM inventory i 
     LEFT JOIN users u ON i.created_by = u.id 
     WHERE i.name LIKE ? OR i.description LIKE ? OR i.category LIKE ?
     ORDER BY i.created_at DESC`,
    [searchTerm, searchTerm, searchTerm],
    async (err, items) => {
      if (err) {
        logger.error(`Error buscando items: ${err.message}`);
        return res.status(500).json({
          success: false,
          message: 'Error buscando items'
        });
      }

      await logAudit(req.user.id, 'SEARCH', 'inventory', null, `Búsqueda: ${term}`, req.ip);

      res.json({
        success: true,
        items,
        count: items.length
      });
    }
  );
});

// ========================================
// ESTADÍSTICAS DEL INVENTARIO
// ========================================
router.get('/stats/summary', async (req, res) => {
  db.get(
    `SELECT 
      COUNT(*) as total_items,
      SUM(quantity) as total_quantity,
      SUM(quantity * price) as total_value,
      AVG(price) as average_price
     FROM inventory`,
    [],
    async (err, stats) => {
      if (err) {
        logger.error(`Error obteniendo estadísticas: ${err.message}`);
        return res.status(500).json({
          success: false,
          message: 'Error obteniendo estadísticas'
        });
      }

      await logAudit(req.user.id, 'VIEW_STATS', 'inventory', null, 'Estadísticas consultadas', req.ip);

      res.json({
        success: true,
        stats
      });
    }
  );
});

module.exports = router;
