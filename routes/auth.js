const express = require('express');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { body, validationResult } = require('express-validator');
const { db, logAudit } = require('../utils/database');
const { generateToken, authenticateToken } = require('../utils/auth');
const { validatePasswordComplexity, checkPasswordExpiration } = require('../utils/passwordPolicies');
const logger = require('../utils/logger');

const router = express.Router();

// ========================================
// REGISTRO DE USUARIO
// ========================================
router.post('/register', [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  // Validar errores básicos
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Datos inválidos',
      errors: errors.array()
    });
  }

  const { username, password, email } = req.body;

  // POLÍTICA DE CONTRASEÑAS: Validar complejidad
  const passwordValidation = validatePasswordComplexity(password);
  if (!passwordValidation.isValid) {
    return res.status(400).json({
      success: false,
      message: 'La contraseña no cumple con los requisitos de seguridad',
      errors: passwordValidation.errors,
      strength: passwordValidation.strength
    });
  }

  try {
    // CONFIDENCIALIDAD: Hash de la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Calcular fecha de expiración (90 días desde ahora)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 90);

    db.run(
      `INSERT INTO users (username, password, email, password_changed_at, password_expires_at) 
       VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)`,
      [username, hashedPassword, email, expiresAt.toISOString()],
      async function(err) {
        if (err) {
          logger.error(`Error registrando usuario: ${err.message}`);
          return res.status(400).json({
            success: false,
            message: 'El usuario o email ya existe'
          });
        }

        const userId = this.lastID;

        // Guardar en histórico de contraseñas
        db.run(
          'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)',
          [userId, hashedPassword]
        );

        // Registrar en auditoría
        await logAudit(userId, 'REGISTER', 'users', userId, `Usuario ${username} registrado`, req.ip);
        
        logger.info(`Usuario registrado: ${username} - Fuerza de contraseña: ${passwordValidation.strength.level}`);
        res.status(201).json({
          success: true,
          message: 'Usuario registrado exitosamente',
          userId: userId,
          passwordStrength: passwordValidation.strength
        });
      }
    );
  } catch (error) {
    logger.error(`Error en registro: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// ========================================
// LOGIN - PASO 1: Verificar credenciales
// ========================================
router.post('/login', [
  body('username').trim().escape(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Datos inválidos'
    });
  }

  const { username, password } = req.body;

  db.get(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (err, user) => {
      if (err) {
        logger.error(`Error en login: ${err.message}`);
        return res.status(500).json({
          success: false,
          message: 'Error interno del servidor'
        });
      }

      if (!user) {
        logger.warn(`Intento de login fallido para usuario: ${username} - IP: ${req.ip}`);
        return res.status(401).json({
          success: false,
          message: 'Credenciales inválidas'
        });
      }

      // POLÍTICA: Verificar si la cuenta está bloqueada
      if (user.locked_until) {
        const lockedUntil = new Date(user.locked_until);
        const now = new Date();
        
        if (now < lockedUntil) {
          const minutesLeft = Math.ceil((lockedUntil - now) / 1000 / 60);
          logger.warn(`Intento de login en cuenta bloqueada: ${username} - IP: ${req.ip}`);
          return res.status(423).json({
            success: false,
            message: `Cuenta bloqueada. Intente nuevamente en ${minutesLeft} minutos.`,
            lockedUntil: lockedUntil
          });
        } else {
          // Desbloquear cuenta si ya pasó el tiempo
          db.run(
            'UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE id = ?',
            [user.id]
          );
          user.failed_login_attempts = 0;
        }
      }

      // CONFIDENCIALIDAD: Verificar contraseña hasheada
      const validPassword = await bcrypt.compare(password, user.password);
      
      if (!validPassword) {
        // Incrementar intentos fallidos
        const newAttempts = (user.failed_login_attempts || 0) + 1;
        
        if (newAttempts >= 5) {
          // Bloquear cuenta por 15 minutos
          const lockUntil = new Date();
          lockUntil.setMinutes(lockUntil.getMinutes() + 15);
          
          db.run(
            'UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?',
            [newAttempts, lockUntil.toISOString(), user.id]
          );
          
          logger.warn(`Cuenta bloqueada por intentos fallidos: ${username} - IP: ${req.ip}`);
          await logAudit(user.id, 'ACCOUNT_LOCKED', 'users', user.id, 'Cuenta bloqueada por intentos fallidos', req.ip);
          
          return res.status(423).json({
            success: false,
            message: 'Cuenta bloqueada por múltiples intentos fallidos. Intente en 15 minutos.'
          });
        } else {
          db.run(
            'UPDATE users SET failed_login_attempts = ? WHERE id = ?',
            [newAttempts, user.id]
          );
          
          logger.warn(`Contraseña incorrecta para usuario: ${username} - Intentos: ${newAttempts}/5 - IP: ${req.ip}`);
          await logAudit(user.id, 'LOGIN_FAILED', 'users', user.id, `Contraseña incorrecta (${newAttempts}/5)`, req.ip);
          
          return res.status(401).json({
            success: false,
            message: `Credenciales inválidas. Intentos restantes: ${5 - newAttempts}`
          });
        }
      }

      // POLÍTICA: Verificar expiración de contraseña
      const expirationCheck = checkPasswordExpiration(user.password_changed_at);
      
      if (expirationCheck.expired) {
        logger.info(`Contraseña expirada para usuario: ${username}`);
        return res.status(403).json({
          success: false,
          message: 'Su contraseña ha expirado. Debe cambiarla antes de continuar.',
          passwordExpired: true,
          userId: user.id,
          daysSinceChange: expirationCheck.daysSinceChange
        });
      }

      // Resetear intentos fallidos
      db.run(
        'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?',
        [user.id]
      );

      // Si MFA está habilitado, requerir código
      if (user.mfa_enabled) {
        // Advertencia de expiración próxima
        const warning = expirationCheck.shouldWarn ? {
          passwordExpiring: true,
          daysUntilExpiration: expirationCheck.daysUntilExpiration
        } : {};

        res.json({
          success: true,
          mfaRequired: true,
          userId: user.id,
          message: 'Ingrese el código MFA',
          ...warning
        });
      } else {
        // Login sin MFA
        const token = generateToken(user);
        
        // Actualizar último login
        db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
        
        await logAudit(user.id, 'LOGIN_SUCCESS', 'users', user.id, 'Login exitoso', req.ip);
        logger.info(`Login exitoso: ${username}`);

        // Advertencia de expiración próxima
        const warning = expirationCheck.shouldWarn ? {
          passwordExpiring: true,
          daysUntilExpiration: expirationCheck.daysUntilExpiration,
          message: `Su contraseña expirará en ${expirationCheck.daysUntilExpiration} días`
        } : {};

        res.json({
          success: true,
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            mfaEnabled: false
          },
          ...warning
        });
      }
    }
  );
});

// ========================================
// LOGIN - PASO 2: Verificar código MFA
// ========================================
router.post('/verify-mfa', [
  body('userId').isInt(),
  body('token').isLength({ min: 6, max: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Datos inválidos'
    });
  }

  const { userId, token } = req.body;

  db.get('SELECT * FROM users WHERE id = ?', [userId], async (err, user) => {
    if (err || !user) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    // Verificar código TOTP
    const verified = speakeasy.totp.verify({
      secret: user.mfa_secret,
      encoding: 'base32',
      token: token,
      window: 2 // Acepta códigos con 2 pasos de diferencia
    });

    if (verified) {
      const authToken = generateToken(user);
      
      db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
      
      await logAudit(user.id, 'MFA_SUCCESS', 'users', user.id, 'MFA verificado exitosamente', req.ip);
      logger.info(`MFA verificado para usuario: ${user.username}`);

      res.json({
        success: true,
        token: authToken,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          mfaEnabled: true
        }
      });
    } else {
      await logAudit(user.id, 'MFA_FAILED', 'users', user.id, 'Código MFA inválido', req.ip);
      logger.warn(`Código MFA inválido para usuario: ${user.username} - IP: ${req.ip}`);
      
      res.status(401).json({
        success: false,
        message: 'Código MFA inválido'
      });
    }
  });
});

// ========================================
// CONFIGURAR MFA - PASO 1: Generar QR
// ========================================
router.post('/setup-mfa', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  // Generar secreto para TOTP
  const secret = speakeasy.generateSecret({
    name: `Inventory System (${req.user.username})`,
    length: 32
  });

  // Generar código QR
  try {
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    res.json({
      success: true,
      secret: secret.base32,
      qrCode: qrCodeUrl,
      message: 'Escanea el código QR con Google Authenticator o similar'
    });
  } catch (error) {
    logger.error(`Error generando QR para MFA: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error generando código QR'
    });
  }
});

// ========================================
// CONFIGURAR MFA - PASO 2: Activar
// ========================================
router.post('/activate-mfa', authenticateToken, [
  body('secret').notEmpty(),
  body('token').isLength({ min: 6, max: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Datos inválidos'
    });
  }

  const { secret, token } = req.body;
  const userId = req.user.id;

  // Verificar que el código es correcto antes de activar
  const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 2
  });

  if (verified) {
    db.run(
      'UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?',
      [secret, userId],
      async function(err) {
        if (err) {
          logger.error(`Error activando MFA: ${err.message}`);
          return res.status(500).json({
            success: false,
            message: 'Error activando MFA'
          });
        }

        await logAudit(userId, 'MFA_ENABLED', 'users', userId, 'MFA habilitado', req.ip);
        logger.info(`MFA habilitado para usuario ID: ${userId}`);

        res.json({
          success: true,
          message: 'MFA activado exitosamente'
        });
      }
    );
  } else {
    res.status(401).json({
      success: false,
      message: 'Código de verificación inválido'
    });
  }
});

// ========================================
// DESACTIVAR MFA
// ========================================
router.post('/disable-mfa', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  db.run(
    'UPDATE users SET mfa_secret = NULL, mfa_enabled = 0 WHERE id = ?',
    [userId],
    async function(err) {
      if (err) {
        logger.error(`Error desactivando MFA: ${err.message}`);
        return res.status(500).json({
          success: false,
          message: 'Error desactivando MFA'
        });
      }

      await logAudit(userId, 'MFA_DISABLED', 'users', userId, 'MFA deshabilitado', req.ip);
      logger.info(`MFA deshabilitado para usuario ID: ${userId}`);

      res.json({
        success: true,
        message: 'MFA desactivado exitosamente'
      });
    }
  );
});

// ========================================
// OBTENER INFORMACIÓN DEL USUARIO
// ========================================
router.get('/me', authenticateToken, (req, res) => {
  db.get(
    'SELECT id, username, email, mfa_enabled, created_at, last_login, password_changed_at, password_expires_at FROM users WHERE id = ?',
    [req.user.id],
    (err, user) => {
      if (err || !user) {
        return res.status(404).json({
          success: false,
          message: 'Usuario no encontrado'
        });
      }

      // Verificar expiración de contraseña
      const expirationCheck = checkPasswordExpiration(user.password_changed_at);

      res.json({
        success: true,
        user: {
          ...user,
          passwordExpiration: expirationCheck
        }
      });
    }
  );
});

// ========================================
// CAMBIAR CONTRASEÑA
// ========================================
router.post('/change-password', authenticateToken, [
  body('currentPassword').notEmpty(),
  body('newPassword').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Datos inválidos',
      errors: errors.array()
    });
  }

  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id;

  try {
    // Obtener usuario actual
    db.get('SELECT * FROM users WHERE id = ?', [userId], async (err, user) => {
      if (err || !user) {
        return res.status(404).json({
          success: false,
          message: 'Usuario no encontrado'
        });
      }

      // Verificar contraseña actual
      const validPassword = await bcrypt.compare(currentPassword, user.password);
      if (!validPassword) {
        await logAudit(userId, 'PASSWORD_CHANGE_FAILED', 'users', userId, 'Contraseña actual incorrecta', req.ip);
        return res.status(401).json({
          success: false,
          message: 'Contraseña actual incorrecta'
        });
      }

      // Validar complejidad de nueva contraseña
      const passwordValidation = validatePasswordComplexity(newPassword);
      if (!passwordValidation.isValid) {
        return res.status(400).json({
          success: false,
          message: 'La nueva contraseña no cumple con los requisitos',
          errors: passwordValidation.errors,
          strength: passwordValidation.strength
        });
      }

      // Verificar que no sea la misma contraseña
      const samePassword = await bcrypt.compare(newPassword, user.password);
      if (samePassword) {
        return res.status(400).json({
          success: false,
          message: 'La nueva contraseña debe ser diferente a la actual'
        });
      }

      // Verificar histórico (últimas 5 contraseñas)
      db.all(
        'SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 5',
        [userId],
        async (err, history) => {
          if (err) {
            logger.error('Error consultando histórico de contraseñas:', err);
          }

          // Verificar contra histórico
          if (history && history.length > 0) {
            for (const record of history) {
              const isReused = await bcrypt.compare(newPassword, record.password_hash);
              if (isReused) {
                return res.status(400).json({
                  success: false,
                  message: 'No puede reutilizar ninguna de sus últimas 5 contraseñas'
                });
              }
            }
          }

          // Hash de nueva contraseña
          const hashedPassword = await bcrypt.hash(newPassword, 10);

          // Calcular nueva fecha de expiración
          const expiresAt = new Date();
          expiresAt.setDate(expiresAt.getDate() + 90);

          // Actualizar contraseña
          db.run(
            `UPDATE users SET 
             password = ?, 
             password_changed_at = CURRENT_TIMESTAMP,
             password_expires_at = ?,
             failed_login_attempts = 0,
             locked_until = NULL
             WHERE id = ?`,
            [hashedPassword, expiresAt.toISOString(), userId],
            async function(err) {
              if (err) {
                logger.error('Error actualizando contraseña:', err);
                return res.status(500).json({
                  success: false,
                  message: 'Error actualizando contraseña'
                });
              }

              // Guardar en histórico
              db.run(
                'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)',
                [userId, hashedPassword]
              );

              // Limpiar histórico antiguo (mantener solo últimas 5)
              db.run(
                `DELETE FROM password_history 
                 WHERE user_id = ? AND id NOT IN (
                   SELECT id FROM password_history 
                   WHERE user_id = ? 
                   ORDER BY created_at DESC 
                   LIMIT 5
                 )`,
                [userId, userId]
              );

              await logAudit(userId, 'PASSWORD_CHANGED', 'users', userId, 
                           `Contraseña cambiada - Fuerza: ${passwordValidation.strength.level}`, req.ip);
              
              logger.info(`Contraseña cambiada para usuario ID: ${userId} - Fuerza: ${passwordValidation.strength.level}`);

              res.json({
                success: true,
                message: 'Contraseña actualizada exitosamente',
                passwordStrength: passwordValidation.strength,
                expiresAt: expiresAt
              });
            }
          );
        }
      );
    });
  } catch (error) {
    logger.error('Error en cambio de contraseña:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// ========================================
// VALIDAR CONTRASEÑA (sin guardar)
// ========================================
router.post('/validate-password', (req, res) => {
  const { password } = req.body;
  
  if (!password) {
    return res.status(400).json({
      success: false,
      message: 'Contraseña requerida'
    });
  }

  const validation = validatePasswordComplexity(password);
  
  res.json({
    success: true,
    validation: {
      isValid: validation.isValid,
      errors: validation.errors,
      strength: validation.strength
    }
  });
});

module.exports = router;
