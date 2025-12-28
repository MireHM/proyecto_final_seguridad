// ========================================
// ESTADO DE LA APLICACIÓN
// ========================================
let currentUser = null;
let authToken = null;
let currentMfaUserId = null;
let currentMfaSecret = null;

// ========================================
// UTILIDADES
// ========================================
function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification ${type} show`;
    
    setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}

function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    document.getElementById(screenId).classList.add('active');
}

function showModal(modalId) {
    const modal = document.getElementById(modalId);
    modal.classList.add('active');
}

function hideModal(modalId) {
    const modal = document.getElementById(modalId);
    modal.classList.remove('active');
}

// ========================================
// API CALLS
// ========================================
async function apiCall(endpoint, method = 'GET', data = null, useAuth = true) {
    const headers = {
        'Content-Type': 'application/json'
    };
    
    if (useAuth && authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
    }
    
    const options = {
        method,
        headers
    };
    
    if (data && method !== 'GET') {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(`/api${endpoint}`, options);
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.message || 'Error en la petición');
        }
        
        return result;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// ========================================
// AUTENTICACIÓN
// ========================================
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    try {
        const result = await apiCall('/auth/login', 'POST', { username, password }, false);
        
        if (result.mfaRequired) {
            // Requiere MFA
            currentMfaUserId = result.userId;
            showScreen('mfaScreen');
            showNotification('Ingrese el código MFA', 'info');
            
            // Advertencia de expiración si existe
            if (result.passwordExpiring) {
                setTimeout(() => {
                    showNotification(
                        `⚠️ Su contraseña expirará en ${result.daysUntilExpiration} días`, 
                        'info'
                    );
                }, 2000);
            }
        } else {
            // Login exitoso sin MFA
            authToken = result.token;
            currentUser = result.user;
            showNotification('Sesión iniciada correctamente', 'success');
            
            // Advertencia de expiración si existe
            if (result.passwordExpiring) {
                setTimeout(() => {
                    showNotification(
                        `⚠️ ${result.message}`, 
                        'info'
                    );
                }, 2000);
            }
            
            loadMainScreen();
        }
    } catch (error) {
        // Manejar diferentes tipos de errores
        if (error.message.includes('bloqueada')) {
            showNotification('🔒 ' + error.message, 'error');
        } else if (error.message.includes('expirado')) {
            showNotification('⏰ ' + error.message, 'error');
        } else if (error.message.includes('Intentos restantes')) {
            showNotification('⚠️ ' + error.message, 'error');
        } else {
            showNotification(error.message, 'error');
        }
    }
});

// MFA Verification
document.getElementById('mfaForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const token = document.getElementById('mfaCode').value;
    
    try {
        const result = await apiCall('/auth/verify-mfa', 'POST', {
            userId: currentMfaUserId,
            token
        }, false);
        
        authToken = result.token;
        currentUser = result.user;
        showNotification('Autenticación MFA exitosa', 'success');
        loadMainScreen();
    } catch (error) {
        showNotification(error.message, 'error');
    }
});

document.getElementById('cancelMfa').addEventListener('click', () => {
    currentMfaUserId = null;
    document.getElementById('mfaCode').value = '';
    showScreen('loginScreen');
});

// Register
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('regUsername').value;
    const email = document.getElementById('regEmail').value;
    const password = document.getElementById('regPassword').value;
    
    try {
        const result = await apiCall('/auth/register', 'POST', { username, email, password }, false);
        
        showNotification('Cuenta creada exitosamente', 'success');
        
        // Mostrar fuerza de contraseña si está disponible
        if (result.passwordStrength) {
            setTimeout(() => {
                showNotification(
                    `Contraseña registrada con fuerza: ${result.passwordStrength.level}`, 
                    'info'
                );
            }, 2000);
        }
        
        showScreen('loginScreen');
        document.getElementById('registerForm').reset();
        document.getElementById('strengthBar').style.width = '0%';
        document.getElementById('strengthText').textContent = '';
        document.getElementById('passwordErrors').innerHTML = '';
    } catch (error) {
        // Si hay errores de validación, mostrarlos
        if (error.message.includes('requisitos de seguridad')) {
            const errorDiv = document.getElementById('passwordErrors');
            errorDiv.innerHTML = '<p style="color: #f56565; font-weight: 600;">La contraseña no cumple los requisitos</p>';
        }
        showNotification(error.message, 'error');
    }
});

document.getElementById('showRegister').addEventListener('click', (e) => {
    e.preventDefault();
    showScreen('registerScreen');
});

document.getElementById('backToLogin').addEventListener('click', () => {
    showScreen('loginScreen');
});

// ========================================
// VALIDACIÓN DE CONTRASEÑA EN TIEMPO REAL
// ========================================
let passwordValidationTimeout;

document.getElementById('regPassword').addEventListener('input', (e) => {
    clearTimeout(passwordValidationTimeout);
    const password = e.target.value;
    
    if (password.length === 0) {
        document.getElementById('strengthBar').style.width = '0%';
        document.getElementById('strengthText').textContent = '';
        document.getElementById('passwordErrors').innerHTML = '';
        return;
    }
    
    passwordValidationTimeout = setTimeout(async () => {
        try {
            const result = await apiCall('/auth/validate-password', 'POST', { password }, false);
            
            if (result.validation) {
                const { strength, errors, isValid } = result.validation;
                
                // Actualizar barra de fuerza
                const strengthBar = document.getElementById('strengthBar');
                strengthBar.style.width = strength.score + '%';
                strengthBar.style.backgroundColor = strength.color;
                
                // Texto de fuerza
                document.getElementById('strengthText').textContent = 
                    `Fuerza: ${strength.level} (${strength.score}/100)`;
                document.getElementById('strengthText').style.color = strength.color;
                
                // Mostrar errores si hay
                if (!isValid && errors.length > 0) {
                    document.getElementById('passwordErrors').innerHTML = 
                        '<ul>' + errors.map(err => `<li>${err}</li>`).join('') + '</ul>';
                } else {
                    document.getElementById('passwordErrors').innerHTML = 
                        '<p style="color: #48bb78; font-size: 13px;">✓ Contraseña válida</p>';
                }
            }
        } catch (error) {
            console.error('Error validando contraseña:', error);
        }
    }, 500);
});

// Validación similar para nueva contraseña en modal de cambio
document.getElementById('newPassword')?.addEventListener('input', (e) => {
    clearTimeout(passwordValidationTimeout);
    const password = e.target.value;
    
    if (password.length === 0) {
        document.getElementById('newPasswordStrengthBar').style.width = '0%';
        document.getElementById('newPasswordStrengthText').textContent = '';
        document.getElementById('newPasswordErrors').innerHTML = '';
        return;
    }
    
    passwordValidationTimeout = setTimeout(async () => {
        try {
            const result = await apiCall('/auth/validate-password', 'POST', { password }, false);
            
            if (result.validation) {
                const { strength, errors, isValid } = result.validation;
                
                const strengthBar = document.getElementById('newPasswordStrengthBar');
                strengthBar.style.width = strength.score + '%';
                strengthBar.style.backgroundColor = strength.color;
                
                document.getElementById('newPasswordStrengthText').textContent = 
                    `Fuerza: ${strength.level} (${strength.score}/100)`;
                document.getElementById('newPasswordStrengthText').style.color = strength.color;
                
                if (!isValid && errors.length > 0) {
                    document.getElementById('newPasswordErrors').innerHTML = 
                        '<ul>' + errors.map(err => `<li>${err}</li>`).join('') + '</ul>';
                } else {
                    document.getElementById('newPasswordErrors').innerHTML = 
                        '<p style="color: #48bb78; font-size: 13px;">✓ Contraseña válida</p>';
                }
            }
        } catch (error) {
            console.error('Error validando contraseña:', error);
        }
    }, 500);
});

// Logout
document.getElementById('logoutBtn').addEventListener('click', () => {
    authToken = null;
    currentUser = null;
    showScreen('loginScreen');
    showNotification('Sesión cerrada', 'info');
});

// ========================================
// PANTALLA PRINCIPAL
// ========================================
async function loadMainScreen() {
    showScreen('mainScreen');
    document.getElementById('userDisplay').textContent = `👤 ${currentUser.username}`;
    
    // Mostrar/ocultar botón de MFA según estado
    const mfaBtn = document.getElementById('mfaButton');
    if (currentUser.mfaEnabled) {
        mfaBtn.textContent = '🔐 MFA Activado';
    } else {
        mfaBtn.textContent = '🔐 Configurar MFA';
    }
    
    await loadInventory();
}

// ========================================
// INVENTARIO
// ========================================
async function loadInventory() {
    try {
        const result = await apiCall('/inventory/');
        displayInventory(result.items);
    } catch (error) {
        showNotification('Error cargando inventario', 'error');
    }
}

function displayInventory(items) {
    const tbody = document.getElementById('inventoryBody');
    
    if (items.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center;">No hay productos en el inventario</td></tr>';
        return;
    }
    
    tbody.innerHTML = items.map(item => `
        <tr>
            <td>${item.id}</td>
            <td>${item.name}</td>
            <td>${item.description || '-'}</td>
            <td>${item.quantity}</td>
            <td>$${parseFloat(item.price).toFixed(2)}</td>
            <td>${item.category}</td>
            <td>${item.created_by_username || 'N/A'}</td>
            <td>
                <button class="action-btn edit-btn" onclick="editItem(${item.id})">Editar</button>
                <button class="action-btn delete-btn" onclick="deleteItem(${item.id})">Eliminar</button>
            </td>
        </tr>
    `).join('');
}

// Agregar item
document.getElementById('addItemBtn').addEventListener('click', () => {
    document.getElementById('modalTitle').textContent = 'Agregar Producto';
    document.getElementById('itemForm').reset();
    document.getElementById('itemId').value = '';
    showModal('itemModal');
});

// Cerrar modal
document.querySelectorAll('.close').forEach(btn => {
    btn.addEventListener('click', function() {
        const modal = this.closest('.modal');
        modal.classList.remove('active');
    });
});

document.getElementById('cancelBtn').addEventListener('click', () => {
    hideModal('itemModal');
});

// Guardar item
document.getElementById('itemForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const itemId = document.getElementById('itemId').value;
    const data = {
        name: document.getElementById('itemName').value,
        description: document.getElementById('itemDescription').value,
        quantity: parseInt(document.getElementById('itemQuantity').value),
        price: parseFloat(document.getElementById('itemPrice').value),
        category: document.getElementById('itemCategory').value
    };
    
    try {
        if (itemId) {
            // Actualizar
            await apiCall(`/inventory/${itemId}`, 'PUT', data);
            showNotification('Producto actualizado exitosamente', 'success');
        } else {
            // Crear
            await apiCall('/inventory/', 'POST', data);
            showNotification('Producto creado exitosamente', 'success');
        }
        
        hideModal('itemModal');
        await loadInventory();
    } catch (error) {
        showNotification(error.message, 'error');
    }
});

// Editar item
window.editItem = async function(id) {
    try {
        const result = await apiCall(`/inventory/${id}`);
        const item = result.item;
        
        document.getElementById('modalTitle').textContent = 'Editar Producto';
        document.getElementById('itemId').value = item.id;
        document.getElementById('itemName').value = item.name;
        document.getElementById('itemDescription').value = item.description || '';
        document.getElementById('itemQuantity').value = item.quantity;
        document.getElementById('itemPrice').value = item.price;
        document.getElementById('itemCategory').value = item.category;
        
        showModal('itemModal');
    } catch (error) {
        showNotification('Error cargando producto: ' + error.message, 'error');
    }
};

// Eliminar item
window.deleteItem = async function(id) {
    if (!confirm('¿Está seguro de eliminar este producto?')) {
        return;
    }
    
    try {
        await apiCall(`/inventory/${id}`, 'DELETE');
        showNotification('Producto eliminado exitosamente', 'success');
        await loadInventory();
    } catch (error) {
        showNotification('Error eliminando producto: ' + error.message, 'error');
    }
};

// Buscar
let searchTimeout;
document.getElementById('searchInput').addEventListener('input', (e) => {
    clearTimeout(searchTimeout);
    const term = e.target.value.trim();
    
    if (term.length < 2) {
        loadInventory();
        return;
    }
    
    searchTimeout = setTimeout(async () => {
        try {
            const result = await apiCall(`/inventory/search/${encodeURIComponent(term)}`);
            displayInventory(result.items);
            showNotification(`${result.count} resultado(s) encontrado(s)`, 'info');
        } catch (error) {
            showNotification('Error en la búsqueda', 'error');
        }
    }, 500);
});

// Estadísticas
document.getElementById('statsBtn').addEventListener('click', async () => {
    const panel = document.getElementById('statsPanel');
    
    if (panel.style.display === 'none') {
        try {
            const result = await apiCall('/inventory/stats/summary');
            const stats = result.stats;
            
            document.getElementById('statTotalItems').textContent = stats.total_items || 0;
            document.getElementById('statTotalQuantity').textContent = stats.total_quantity || 0;
            document.getElementById('statTotalValue').textContent = 
                `$${parseFloat(stats.total_value || 0).toFixed(2)}`;
            document.getElementById('statAvgPrice').textContent = 
                `$${parseFloat(stats.average_price || 0).toFixed(2)}`;
            
            panel.style.display = 'block';
        } catch (error) {
            showNotification('Error cargando estadísticas', 'error');
        }
    } else {
        panel.style.display = 'none';
    }
});

// ========================================
// CONFIGURACIÓN MFA
// ========================================
document.getElementById('mfaButton').addEventListener('click', () => {
    showModal('mfaSetupModal');
    document.getElementById('mfaStep1').style.display = 'block';
    document.getElementById('mfaStep2').style.display = 'none';
    
    // Si ya tiene MFA, mostrar opción de desactivar
    if (currentUser.mfaEnabled) {
        document.getElementById('disableMfaBtn').style.display = 'inline-block';
    }
});

// ========================================
// CAMBIAR CONTRASEÑA
// ========================================
document.getElementById('changePasswordBtn').addEventListener('click', () => {
    showModal('changePasswordModal');
    document.getElementById('changePasswordForm').reset();
    document.getElementById('newPasswordStrengthBar').style.width = '0%';
    document.getElementById('newPasswordStrengthText').textContent = '';
    document.getElementById('newPasswordErrors').innerHTML = '';
});

document.getElementById('closeChangePassword').addEventListener('click', () => {
    hideModal('changePasswordModal');
});

document.getElementById('cancelChangePassword').addEventListener('click', () => {
    hideModal('changePasswordModal');
});

document.getElementById('changePasswordForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    // Verificar que las contraseñas coincidan
    if (newPassword !== confirmPassword) {
        showNotification('Las contraseñas no coinciden', 'error');
        return;
    }
    
    try {
        const result = await apiCall('/auth/change-password', 'POST', {
            currentPassword,
            newPassword
        });
        
        showNotification('Contraseña actualizada exitosamente', 'success');
        hideModal('changePasswordModal');
        document.getElementById('changePasswordForm').reset();
        
        // Mostrar información sobre la fuerza
        if (result.passwordStrength) {
            setTimeout(() => {
                showNotification(
                    `Fuerza de contraseña: ${result.passwordStrength.level}`, 
                    'info'
                );
            }, 2000);
        }
    } catch (error) {
        showNotification(error.message, 'error');
    }
});

document.getElementById('closeMfaSetup').addEventListener('click', () => {
    hideModal('mfaSetupModal');
});

document.getElementById('generateQrBtn').addEventListener('click', async () => {
    try {
        const result = await apiCall('/auth/setup-mfa', 'POST');
        
        currentMfaSecret = result.secret;
        
        // Mostrar QR
        document.getElementById('qrCodeContainer').innerHTML = 
            `<img src="${result.qrCode}" alt="QR Code">`;
        document.getElementById('manualSecret').textContent = result.secret;
        
        document.getElementById('mfaStep1').style.display = 'none';
        document.getElementById('mfaStep2').style.display = 'block';
        
        showNotification('Código QR generado', 'success');
    } catch (error) {
        showNotification('Error generando código QR', 'error');
    }
});

document.getElementById('verifyMfaBtn').addEventListener('click', async () => {
    const token = document.getElementById('verifyToken').value;
    
    if (token.length !== 6) {
        showNotification('El código debe tener 6 dígitos', 'error');
        return;
    }
    
    try {
        await apiCall('/auth/activate-mfa', 'POST', {
            secret: currentMfaSecret,
            token
        });
        
        currentUser.mfaEnabled = true;
        document.getElementById('mfaButton').textContent = '🔐 MFA Activado';
        
        showNotification('MFA activado exitosamente', 'success');
        hideModal('mfaSetupModal');
    } catch (error) {
        showNotification(error.message, 'error');
    }
});

document.getElementById('disableMfaBtn').addEventListener('click', async () => {
    if (!confirm('¿Está seguro de desactivar MFA? Esto reducirá la seguridad de su cuenta.')) {
        return;
    }
    
    try {
        await apiCall('/auth/disable-mfa', 'POST');
        
        currentUser.mfaEnabled = false;
        document.getElementById('mfaButton').textContent = '🔐 Configurar MFA';
        
        showNotification('MFA desactivado', 'info');
        hideModal('mfaSetupModal');
    } catch (error) {
        showNotification('Error desactivando MFA', 'error');
    }
});

// ========================================
// GESTION DE ROLES
// ========================================

// Abrir modal de roles
document.getElementById('rolesBtn')?.addEventListener('click', async () => {
    showModal('rolesModal');
    await loadRoles();
    await loadPermissionsMatrix();
    await loadAvailablePermissions();
});

// Cerrar modal de roles
document.getElementById('closeRolesModal')?.addEventListener('click', () => {
    hideModal('rolesModal');
});

// Tabs de roles
document.querySelectorAll('.tab-button').forEach(button => {
    button.addEventListener('click', () => {
        const tabId = button.getAttribute('data-tab');
        
        // Actualizar botones
        document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        
        // Actualizar contenido
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        document.getElementById(tabId).classList.add('active');
    });
});

// Cargar lista de roles
async function loadRoles() {
    try {
        const response = await apiCall('/roles', 'GET');
        const roles = response.roles;
        
        const container = document.getElementById('rolesListContainer');
        
        if (roles.length === 0) {
            container.innerHTML = '<p>No hay roles disponibles</p>';
            return;
        }
        
        container.innerHTML = `
            <div class="roles-grid">
                ${roles.map(role => `
                    <div class="role-card">
                        <div class="role-card-header">
                            <div>
                                <h4 class="role-card-title">${role.name}</h4>
                                ${role.is_system ? '<span class="role-badge system">SISTEMA</span>' : '<span class="role-badge">CUSTOM</span>'}
                            </div>
                        </div>
                        <p class="role-description">${role.description || 'Sin descripción'}</p>
                        <div class="role-permissions">
                            <div class="role-permissions-title">Permisos</div>
                            <div class="permissions-count">
                                <span>${role.permissions.length}</span>
                                <span>permisos asignados</span>
                            </div>
                            <div class="permissions-list">
                                ${role.permissions.slice(0, 5).map(perm => `
                                    <span class="permission-tag">${perm}</span>
                                `).join('')}
                                ${role.permissions.length > 5 ? `<span class="permission-tag">+${role.permissions.length - 5} más</span>` : ''}
                            </div>
                        </div>
                        ${!role.is_system ? `
                            <div class="role-actions">
                                <button class="btn btn-small" onclick="editRole(${role.id})">Editar</button>
                                <button class="btn btn-small btn-danger" onclick="deleteRole(${role.id}, '${role.name}')">Eliminar</button>
                            </div>
                        ` : ''}
                    </div>
                `).join('')}
            </div>
        `;
    } catch (error) {
        document.getElementById('rolesListContainer').innerHTML = 
            '<p class="error">Error cargando roles. Verifica que tengas permisos.</p>';
    }
}

// Cargar matriz de permisos
async function loadPermissionsMatrix() {
    try {
        const response = await apiCall('/roles', 'GET');
        const roles = response.roles;
        
        // Obtener todos los permisos únicos
        const allPermissions = new Set();
        roles.forEach(role => {
            role.permissions.forEach(perm => allPermissions.add(perm));
        });
        
        const permissionsArray = Array.from(allPermissions).sort();
        
        const container = document.getElementById('permissionsMatrixContainer');
        
        container.innerHTML = `
            <div class="permissions-matrix">
                <table class="permissions-table">
                    <thead>
                        <tr>
                            <th>Permiso</th>
                            ${roles.map(role => `<th>${role.name}</th>`).join('')}
                        </tr>
                    </thead>
                    <tbody>
                        ${permissionsArray.map(permission => `
                            <tr>
                                <td><strong>${permission}</strong></td>
                                ${roles.map(role => `
                                    <td style="text-align: center;">
                                        ${role.permissions.includes(permission) 
                                            ? '<span class="permission-check">✓</span>' 
                                            : '<span class="permission-cross">—</span>'}
                                    </td>
                                `).join('')}
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } catch (error) {
        document.getElementById('permissionsMatrixContainer').innerHTML = 
            '<p class="error">Error cargando matriz de permisos</p>';
    }
}

// Cargar permisos disponibles para crear rol
async function loadAvailablePermissions() {
    try {
        const response = await apiCall('/roles/permissions/available', 'GET');
        const permissions = response.permissions;
        
        const container = document.getElementById('permissionsCheckboxes');
        
        container.innerHTML = Object.entries(permissions).map(([category, perms]) => `
            <div class="permission-category">
                <h5>${category.charAt(0).toUpperCase() + category.slice(1)}</h5>
                ${perms.map(perm => `
                    <div class="permission-checkbox">
                        <input type="checkbox" 
                               id="perm-${perm.key}" 
                               name="permissions" 
                               value="${perm.key}">
                        <label for="perm-${perm.key}">${perm.description}</label>
                    </div>
                `).join('')}
            </div>
        `).join('');
    } catch (error) {
        document.getElementById('permissionsCheckboxes').innerHTML = 
            '<p class="error">Error cargando permisos disponibles</p>';
    }
}

// Crear nuevo rol
document.getElementById('createRoleForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const name = document.getElementById('roleName').value.trim().toUpperCase();
    const description = document.getElementById('roleDescription').value.trim();
    
    // Obtener permisos seleccionados
    const selectedPermissions = Array.from(
        document.querySelectorAll('input[name="permissions"]:checked')
    ).map(cb => cb.value);
    
    if (selectedPermissions.length === 0) {
        showNotification('Debes seleccionar al menos un permiso', 'error');
        return;
    }
    
    try {
        await apiCall('/roles', 'POST', {
            name,
            description,
            permissions: selectedPermissions
        });
        
        showNotification('Rol creado exitosamente', 'success');
        
        // Resetear formulario
        document.getElementById('createRoleForm').reset();
        document.querySelectorAll('input[name="permissions"]').forEach(cb => cb.checked = false);
        
        // Recargar lista de roles
        await loadRoles();
        await loadPermissionsMatrix();
        
        // Volver a la pestaña de lista
        document.querySelector('.tab-button[data-tab="roles-list"]').click();
        
    } catch (error) {
        showNotification(error.message || 'Error creando rol', 'error');
    }
});

// Editar rol (simplificado - solo muestra info)
window.editRole = async function(roleId) {
    showNotification('Función de edición disponible. Implementa según necesites.', 'info');
};

// Eliminar rol
window.deleteRole = async function(roleId, roleName) {
    if (!confirm(`¿Estás seguro de eliminar el rol "${roleName}"?`)) {
        return;
    }
    
    try {
        await apiCall(`/roles/${roleId}`, 'DELETE');
        showNotification('Rol eliminado exitosamente', 'success');
        await loadRoles();
        await loadPermissionsMatrix();
    } catch (error) {
        showNotification(error.message || 'Error eliminando rol', 'error');
    }
};

// ========================================
// CERRAR MODALES AL HACER CLICK FUERA
// ========================================
window.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal')) {
        e.target.classList.remove('active');
    }
});
