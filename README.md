# Sistema de Inventario Seguro - CIA Triad + MFA

Sistema de gestión de inventario con implementación de la tríada CIA (Confidencialidad, Integridad, Disponibilidad) y autenticación multifactor (MFA).

## 🔒 Características de Seguridad Implementadas

### 1. CONFIDENCIALIDAD
- ✅ Encriptación de contraseñas con bcrypt
- ✅ Tokens JWT para autenticación
- ✅ Protección de rutas con middleware de autenticación
- ✅ Helmet.js para headers de seguridad
- ✅ Autenticación de dos factores (2FA/MFA) con TOTP

### 2. INTEGRIDAD
- ✅ Validación de datos de entrada con express-validator
- ✅ Constraints a nivel de base de datos (CHECK, NOT NULL, FOREIGN KEY)
- ✅ Sanitización de inputs
- ✅ Firma de tokens JWT
- ✅ Verificación de códigos MFA

### 3. DISPONIBILIDAD
- ✅ Sistema de logging con Winston
- ✅ Rate limiting para prevenir ataques DoS
- ✅ Manejo robusto de errores
- ✅ Auditoría completa de acciones
- ✅ Base de datos con persistencia

### 4. AUTENTICACIÓN MULTIFACTOR (MFA)
- ✅ TOTP (Time-based One-Time Password)
- ✅ Generación de códigos QR
- ✅ Compatible con Google Authenticator, Microsoft Authenticator, etc.
- ✅ Activación/desactivación controlada

## 📋 Requisitos Previos

- Node.js 14 o superior
- npm (viene con Node.js)

## 🚀 Instalación y Ejecución

### Paso 1: Instalar dependencias
```bash
npm install
```

### Paso 2: Iniciar el servidor
```bash
npm start
```

El servidor estará disponible en: **http://localhost:3000**

## 👤 Credenciales de Prueba

**Usuario:** `admin`  
**Contraseña:** `Admin123!`

## 📱 Configurar MFA (Opcional)

1. Inicia sesión con las credenciales de prueba
2. Haz clic en "🔐 Configurar MFA"
3. Descarga Google Authenticator en tu móvil:
   - [Android](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2)
   - [iOS](https://apps.apple.com/app/google-authenticator/id388497605)
4. Genera el código QR y escanéalo
5. Ingresa el código de 6 dígitos para activar MFA

## 📂 Estructura del Proyecto

```
inventory-security-system/
├── server.js              # Servidor principal con configuraciones de seguridad
├── package.json           # Dependencias del proyecto
├── database.sqlite        # Base de datos SQLite (se crea automáticamente)
├── routes/
│   ├── auth.js           # Rutas de autenticación y MFA
│   └── inventory.js      # Rutas de gestión de inventario
├── utils/
│   ├── database.js       # Configuración de BD y auditoría
│   ├── logger.js         # Sistema de logging (DISPONIBILIDAD)
│   └── auth.js           # Middleware de autenticación JWT
├── public/
│   ├── index.html        # Interfaz de usuario
│   ├── styles.css        # Estilos
│   └── app.js            # Lógica del frontend
└── logs/
    ├── application.log   # Log de actividad del sistema
    └── error.log         # Log de errores
```

## 🎯 Funcionalidades del Sistema

### Gestión de Usuarios
- Registro de nuevos usuarios
- Login con validación de credenciales
- Autenticación MFA opcional
- Gestión de sesiones con JWT

### Gestión de Inventario
- ➕ Crear productos
- ✏️ Editar productos
- 🗑️ Eliminar productos
- 🔍 Buscar productos
- 📊 Ver estadísticas

### Auditoría y Logs
- Todas las acciones se registran en `audit_log`
- Logs de aplicación en `logs/application.log`
- Logs de errores en `logs/error.log`

## 🔐 Implementación de la Tríada CIA

### CONFIDENCIALIDAD - Código a Mostrar

**1. Hash de contraseñas (utils/database.js, línea ~80)**
```javascript
const hashedPassword = await bcrypt.hash(password, 10);
```

**2. Verificación de contraseña (routes/auth.js, línea ~108)**
```javascript
const validPassword = await bcrypt.compare(password, user.password);
```

**3. Generación de JWT (utils/auth.js, línea ~37)**
```javascript
function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, email: user.email },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}
```

**4. Middleware de autenticación (utils/auth.js, línea ~15)**
```javascript
function authenticateToken(req, res, next) {
  const token = authHeader && authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    // Verificación del token
  });
}
```

### INTEGRIDAD - Código a Mostrar

**1. Validación de datos (routes/inventory.js, línea ~64)**
```javascript
router.post('/', [
  body('name').trim().notEmpty().isLength({ min: 2, max: 100 }).escape(),
  body('quantity').isInt({ min: 0 }).toInt(),
  body('price').isFloat({ min: 0 }).toFloat(),
  // ...
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
});
```

**2. Constraints de base de datos (utils/database.js, línea ~37)**
```javascript
CREATE TABLE IF NOT EXISTS inventory (
  quantity INTEGER NOT NULL CHECK(quantity >= 0),
  price REAL NOT NULL CHECK(price >= 0),
  FOREIGN KEY (created_by) REFERENCES users(id)
)
```

**3. Validación de contraseña fuerte (routes/auth.js, línea ~16)**
```javascript
body('password').isLength({ min: 8 })
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
```

### DISPONIBILIDAD - Código a Mostrar

**1. Sistema de logging (utils/logger.js)**
```javascript
const logger = winston.createLogger({
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/application.log' })
  ]
});
```

**2. Rate limiting (server.js, línea ~24)**
```javascript
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Demasiadas peticiones, intenta más tarde.'
});
```

**3. Auditoría de acciones (utils/database.js, línea ~98)**
```javascript
function logAudit(userId, action, tableName, recordId, details, ipAddress) {
  db.run(
    `INSERT INTO audit_log (user_id, action, table_name, record_id, details, ip_address) 
     VALUES (?, ?, ?, ?, ?, ?)`,
    [userId, action, tableName, recordId, details, ipAddress]
  );
}
```

**4. Manejo de errores (server.js, línea ~63)**
```javascript
app.use((err, req, res, next) => {
  logger.error(`Error: ${err.message}`);
  res.status(500).json({
    success: false,
    message: 'Error interno del servidor'
  });
});
```

### MFA - Código a Mostrar

**1. Generación de secreto TOTP (routes/auth.js, línea ~185)**
```javascript
const secret = speakeasy.generateSecret({
  name: `Inventory System (${req.user.username})`,
  length: 32
});
```

**2. Verificación de código MFA (routes/auth.js, línea ~145)**
```javascript
const verified = speakeasy.totp.verify({
  secret: user.mfa_secret,
  encoding: 'base32',
  token: token,
  window: 2
});
```

**3. Generación de código QR (routes/auth.js, línea ~192)**
```javascript
const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
```

**Desarrollado para práctica académica de Seguridad en Aplicaciones Web**
