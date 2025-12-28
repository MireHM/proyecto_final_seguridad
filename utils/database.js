const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const logger = require('./logger');

const dbPath = path.join(__dirname, '..', 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    logger.error('Error al conectar a la base de datos:', err);
  } else {
    logger.info('✅ Conectado a la base de datos SQLite');
  }
});

// ========================================
// INICIALIZACIÓN DE TABLAS
// ========================================
db.serialize(() => {
  // Tabla de roles (A01: Control de Acceso)
  db.run(`
    CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      permissions TEXT NOT NULL,
      is_system INTEGER DEFAULT 0,
      active INTEGER DEFAULT 1,
      created_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (created_by) REFERENCES users(id)
    )
  `, (err) => {
    if (err) {
      logger.error('Error creando tabla roles:', err);
    } else {
      logger.info('✅ Tabla roles creada/verificada');
    }
  });

  // Tabla de usuarios con campos para MFA y políticas de contraseñas
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      role TEXT DEFAULT 'USER',
      mfa_secret TEXT,
      mfa_enabled INTEGER DEFAULT 0,
      password_changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      password_expires_at DATETIME,
      failed_login_attempts INTEGER DEFAULT 0,
      locked_until DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME,
      FOREIGN KEY (role) REFERENCES roles(name)
    )
  `, (err) => {
    if (err) {
      logger.error('Error creando tabla users:', err);
    } else {
      logger.info('✅ Tabla users creada/verificada');
    }
  });

  // Tabla de histórico de contraseñas
  db.run(`
    CREATE TABLE IF NOT EXISTS password_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `, (err) => {
    if (err) {
      logger.error('Error creando tabla password_history:', err);
    } else {
      logger.info('✅ Tabla password_history creada/verificada');
    }
  });

  // Tabla de inventario
  // INTEGRIDAD: Constraints y validaciones a nivel de BD
  db.run(`
    CREATE TABLE IF NOT EXISTS inventory (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      quantity INTEGER NOT NULL CHECK(quantity >= 0),
      price REAL NOT NULL CHECK(price >= 0),
      category TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (created_by) REFERENCES users(id)
    )
  `, (err) => {
    if (err) {
      logger.error('Error creando tabla inventory:', err);
    } else {
      logger.info('✅ Tabla inventory creada/verificada');
    }
  });

  // Tabla de auditoría (DISPONIBILIDAD + INTEGRIDAD)
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      table_name TEXT NOT NULL,
      record_id INTEGER,
      details TEXT,
      ip_address TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `, (err) => {
    if (err) {
      logger.error('Error creando tabla audit_log:', err);
    } else {
      logger.info('✅ Tabla audit_log creada/verificada');
    }
  });

  // Inicializar datos de demostración
  initializeDemoData();
});

// ========================================
// INICIALIZAR ROLES POR DEFECTO
// ========================================
async function createDefaultRoles() {
  const { DEFAULT_ROLES } = require('./defaultRoles');
  
  return new Promise((resolve, reject) => {
    db.get('SELECT COUNT(*) as count FROM roles', async (err, result) => {
      if (err) {
        logger.error('Error verificando roles:', err);
        return reject(err);
      }

      if (result.count > 0) {
        logger.info('Roles ya existen en la base de datos');
        return resolve();
      }

      logger.info('Creando roles del sistema...');
      
      // Crear cada rol
      for (const [roleName, roleData] of Object.entries(DEFAULT_ROLES)) {
        await new Promise((res, rej) => {
          db.run(
            'INSERT INTO roles (name, description, permissions, is_system) VALUES (?, ?, ?, 1)',
            [roleName, roleData.description, JSON.stringify(roleData.permissions)],
            function(err) {
              if (err) {
                logger.error(`Error creando rol ${roleName}:`, err);
                return rej(err);
              }
              logger.info(`✅ Rol creado: ${roleName} con ${roleData.permissions.length} permisos`);
              res();
            }
          );
        });
      }
      
      resolve();
    });
  });
}

// ========================================
// CREAR USUARIO DEMO
// ========================================
async function createDemoUser() {
  const username = 'admin';
  const password = 'Admin123!';
  const email = 'admin@inventory.com';

  return new Promise((resolve, reject) => {
    // Verificar si ya existe
    db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
      if (err) {
        logger.error('Error verificando usuario demo:', err);
        return reject(err);
      }

      if (row) {
        logger.info('Usuario demo ya existe');
        return resolve();
      }

      // Hash de la contraseña (CONFIDENCIALIDAD)
      const hashedPassword = await bcrypt.hash(password, 10);
      
      // Calcular fecha de expiración (90 días)
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 90);
      
      db.run(
        'INSERT INTO users (username, password, email, role, password_changed_at, password_expires_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?)',
        [username, hashedPassword, email, 'ADMIN', expiresAt.toISOString()],
        (err) => {
          if (err) {
            logger.error('Error creando usuario demo:', err);
            return reject(err);
          }
          logger.info('✅ Usuario demo creado: admin / Admin123!');
          resolve();
        }
      );
    });
  });
}

// ========================================
// INICIALIZAR DATOS DE DEMOSTRACIÓN
// ========================================
async function initializeDemoData() {
  try {
    await createDefaultRoles();
    await createDemoUser();
    logger.info('✅ Inicialización de datos completada');
  } catch (error) {
    logger.error('Error en inicialización de datos:', error);
  }
}

// ========================================
// FUNCIÓN PARA REGISTRAR AUDITORÍA
// ========================================
function logAudit(userId, action, tableName, recordId, details, ipAddress) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO audit_log (user_id, action, table_name, record_id, details, ip_address) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [userId, action, tableName, recordId, details, ipAddress],
      function(err) {
        if (err) {
          logger.error('Error registrando auditoría:', err);
          reject(err);
        } else {
          resolve(this.lastID);
        }
      }
    );
  });
}

module.exports = { db, logAudit };
