const winston = require('winston');
const path = require('path');

// ========================================
// DISPONIBILIDAD: Sistema de logging
// ========================================
// Permite rastrear eventos, errores y actividad del sistema

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss'
    }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: 'inventory-system' },
  transports: [
    // Escribir logs de errores en error.log
    new winston.transports.File({ 
      filename: path.join(__dirname, '..', 'logs', 'error.log'), 
      level: 'error' 
    }),
    // Escribir todos los logs en application.log
    new winston.transports.File({ 
      filename: path.join(__dirname, '..', 'logs', 'application.log') 
    })
  ]
});

// Si no estamos en producción, también log a consola
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

module.exports = logger;
