@echo off
echo ======================================
echo SISTEMA DE INVENTARIO SEGURO
echo Inicializando con Gestion de Roles...
echo ======================================
echo.

REM Verificar Node.js
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: Node.js no esta instalado
    echo Por favor instala Node.js desde https://nodejs.org/
    pause
    exit /b 1
)

REM Limpiar base de datos anterior (OPCIONAL - comentar si quieres conservar datos)
echo Limpiando base de datos anterior...
if exist database.sqlite del database.sqlite
echo OK Base de datos limpia
echo.

REM Instalar dependencias
echo Instalando dependencias...
call npm install --silent
echo OK Dependencias instaladas
echo.

REM Iniciar servidor
echo ======================================
echo Iniciando servidor...
echo ======================================
echo.
echo Sistema disponible en: http://localhost:3000
echo.
echo Credenciales por defecto:
echo   Usuario: admin
echo   Contrasena: Admin123!
echo.
echo Roles creados automaticamente:
echo   - ADMIN (16 permisos - acceso total)
echo   - MANAGER (6 permisos - gestion inventario)
echo   - USER (2 permisos - consulta y creacion)
echo   - VIEWER (2 permisos - solo lectura)
echo.
echo Presiona Ctrl+C para detener el servidor
echo ======================================
echo.

node server.js
