// ========================================
// PROTECCIÓN CONTRA SSRF (A10)
// ========================================
// Este sistema NO realiza requests externos desde el servidor.
// Si en el futuro se necesitaran requests externos:
// 1. Usar whitelist de dominios permitidos
// 2. Validar URLs con regex estricto
// 3. No permitir IPs privadas (127.0.0.1, 192.168.x.x)
// 4. Timeout de 5 segundos máximo
// 5. Deshabilitar redirects automáticos
const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const authRoutes = require('./routes/auth');
const inventoryRoutes = require('./routes/inventory');
const logger = require('./utils/logger');

const app = express();
const PORT = 3000;

// ========================================
// SEGURIDAD: CONFIDENCIALIDAD
// ========================================
// Helmet protege contra vulnerabilidades comunes (XSS, clickjacking, etc.)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      scriptSrcAttr: ["'unsafe-inline'"], // Permite onclick, onchange, etc.
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  }
}));

// ========================================
// SEGURIDAD: DISPONIBILIDAD
// ========================================
// Rate limiting para prevenir ataques de fuerza bruta y DoS
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // Máximo 100 requests por ventana
  message: 'Demasiadas peticiones desde esta IP, por favor intenta más tarde.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting más estricto para autenticación
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // Solo 5 intentos de login por 15 minutos
  message: 'Demasiados intentos de autenticación, por favor intenta más tarde.',
  skipSuccessfulRequests: true
});

app.use('/api/auth/login', authLimiter);
app.use('/api/', limiter);

// ========================================
// MIDDLEWARE
// ========================================
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Logging de todas las peticiones (DISPONIBILIDAD - Auditoría)
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});

// ========================================
// RUTAS
// ========================================
const { router: rolesRoutes } = require('./routes/roles');

app.use('/api/auth', authRoutes);
app.use('/api/inventory', inventoryRoutes);
app.use('/api/roles', rolesRoutes);

// Ruta principal
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ========================================
// MANEJO DE ERRORES (DISPONIBILIDAD)
// ========================================
app.use((err, req, res, next) => {
  logger.error(`Error: ${err.message} - Stack: ${err.stack}`);
  res.status(500).json({
    success: false,
    message: 'Error interno del servidor'
  });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Recurso no encontrado'
  });
});

// ========================================
// INICIAR SERVIDOR
// ========================================
app.listen(PORT, () => {
  logger.info(`🚀 Servidor corriendo en http://localhost:${PORT}`);
  console.log(`\n========================================`);
  console.log(`✅ Sistema de Inventario Seguro`);
  console.log(`========================================`);
  console.log(`📍 URL: http://localhost:${PORT}`);
  console.log(`🔒 Seguridad: CIA Triad + MFA habilitado`);
  console.log(`📊 Logs: ./logs/application.log`);
  console.log(`========================================\n`);
});

module.exports = app;
