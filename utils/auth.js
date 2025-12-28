const jwt = require('jsonwebtoken');
const logger = require('./logger');

// ========================================
// CONFIDENCIALIDAD: Secret key para JWT
// ========================================
// En producción, esto debería estar en variables de entorno
const JWT_SECRET = 'tu_clave_secreta_super_segura_cambiar_en_produccion';

// ========================================
// MIDDLEWARE DE AUTENTICACIÓN
// ========================================
// Verifica que el token JWT sea válido (CONFIDENCIALIDAD + INTEGRIDAD)
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    logger.warn(`Intento de acceso sin token - IP: ${req.ip}`);
    return res.status(401).json({
      success: false,
      message: 'Token de autenticación requerido'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      logger.warn(`Token inválido - IP: ${req.ip}`);
      return res.status(403).json({
        success: false,
        message: 'Token inválido o expirado'
      });
    }

    // Agregar información del usuario a la petición
    req.user = user;
    next();
  });
}

// ========================================
// FUNCIÓN PARA GENERAR TOKENS
// ========================================
function generateToken(user) {
  // Token expira en 24 horas
  return jwt.sign(
    { 
      id: user.id, 
      username: user.username,
      email: user.email 
    },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

module.exports = { authenticateToken, generateToken, JWT_SECRET };
