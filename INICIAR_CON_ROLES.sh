#!/bin/bash

echo "======================================"
echo "SISTEMA DE INVENTARIO SEGURO"
echo "Inicializando con Gestion de Roles..."
echo "======================================"
echo ""

# Verificar Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Error: Node.js no esta instalado"
    echo "Por favor instala Node.js desde https://nodejs.org/"
    exit 1
fi

# Limpiar base de datos anterior (OPCIONAL - comentar si quieres conservar datos)
echo "Limpiando base de datos anterior..."
rm -f database.sqlite
echo "✓ Base de datos limpia"
echo ""

# Instalar dependencias
echo "Instalando dependencias..."
npm install --silent
echo "✓ Dependencias instaladas"
echo ""

# Iniciar servidor
echo "======================================"
echo "Iniciando servidor..."
echo "======================================"
echo ""
echo "Sistema disponible en: http://localhost:3000"
echo ""
echo "Credenciales por defecto:"
echo "  Usuario: admin"
echo "  Contraseña: Admin123!"
echo ""
echo "Roles creados automaticamente:"
echo "  - ADMIN (16 permisos - acceso total)"
echo "  - MANAGER (6 permisos - gestion inventario)"
echo "  - USER (2 permisos - consulta y creacion)"
echo "  - VIEWER (2 permisos - solo lectura)"
echo ""
echo "Presiona Ctrl+C para detener el servidor"
echo "======================================"
echo ""

node server.js
