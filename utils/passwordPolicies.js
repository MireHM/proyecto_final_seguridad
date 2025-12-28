// ========================================
// POLÍTICAS DE CONFIGURACIÓN DE CONTRASEÑAS
// ========================================

const passwordPolicies = {
    // COMPLEJIDAD
    complexity: {
        minLength: 8,
        maxLength: 128,
        requireUppercase: true,
        requireLowercase: true,
        requireNumbers: true,
        requireSpecialChars: true,
        specialChars: '@$!%*?&#^()-_=+[]{}|;:,.<>',
        // Patrones prohibidos
        prohibitedPatterns: [
            /^(.)\1+$/, // Todos los caracteres iguales (ej: aaaaa)
            /^(012|123|234|345|456|567|678|789|890)+$/, // Secuencias numéricas
            /^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+$/i, // Secuencias alfabéticas
            /^(qwerty|asdfgh|zxcvbn)+$/i // Teclado
        ],
        commonPasswords: [ // Contraseñas comunes prohibidas
            'password', 'Password123', 'admin123', 'qwerty123', 
            '12345678', 'password123', 'admin', 'letmein',
            'welcome123', 'monkey123', 'dragon123'
        ]
    },

    // LONGITUD
    length: {
        min: 8,
        max: 128,
        recommended: 12
    },

    // TIEMPO DE VIDA ÚTIL (en días)
    expiration: {
        enabled: true,
        maxAge: 90, // 90 días
        warningDays: 7, // Avisar 7 días antes
        graceLogins: 3 // Permitir 3 logins después de expirar
    },

    // HISTÓRICO DE CONTRASEÑAS
    history: {
        enabled: true,
        remember: 5, // Recordar las últimas 5 contraseñas
        preventReuse: true
    },

    // INTENTOS DE LOGIN
    attempts: {
        maxFailedAttempts: 5,
        lockoutDuration: 15, // minutos
        resetAfterSuccess: true
    }
};

// ========================================
// FUNCIONES DE VALIDACIÓN
// ========================================

function validatePasswordComplexity(password) {
    const errors = [];
    const policies = passwordPolicies.complexity;

    // Longitud
    if (password.length < policies.minLength) {
        errors.push(`La contraseña debe tener al menos ${policies.minLength} caracteres`);
    }
    if (password.length > policies.maxLength) {
        errors.push(`La contraseña no puede exceder ${policies.maxLength} caracteres`);
    }

    // Mayúsculas
    if (policies.requireUppercase && !/[A-Z]/.test(password)) {
        errors.push('Debe contener al menos una letra mayúscula');
    }

    // Minúsculas
    if (policies.requireLowercase && !/[a-z]/.test(password)) {
        errors.push('Debe contener al menos una letra minúscula');
    }

    // Números
    if (policies.requireNumbers && !/[0-9]/.test(password)) {
        errors.push('Debe contener al menos un número');
    }

    // Caracteres especiales
    if (policies.requireSpecialChars) {
        const regex = new RegExp(`[${policies.specialChars.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&')}]`);
        if (!regex.test(password)) {
            errors.push(`Debe contener al menos un carácter especial (${policies.specialChars})`);
        }
    }

    // Patrones prohibidos
    for (const pattern of policies.prohibitedPatterns) {
        if (pattern.test(password)) {
            errors.push('La contraseña contiene un patrón no permitido (ej: secuencias, repeticiones)');
            break;
        }
    }

    // Contraseñas comunes
    if (policies.commonPasswords.includes(password.toLowerCase())) {
        errors.push('Esta contraseña es muy común y no está permitida');
    }

    return {
        isValid: errors.length === 0,
        errors: errors,
        strength: calculatePasswordStrength(password)
    };
}

function calculatePasswordStrength(password) {
    let strength = 0;
    
    // Longitud
    if (password.length >= 8) strength += 20;
    if (password.length >= 12) strength += 20;
    if (password.length >= 16) strength += 10;
    
    // Diversidad de caracteres
    if (/[a-z]/.test(password)) strength += 10;
    if (/[A-Z]/.test(password)) strength += 10;
    if (/[0-9]/.test(password)) strength += 10;
    if (/[^A-Za-z0-9]/.test(password)) strength += 20;
    
    // Complejidad adicional
    const uniqueChars = new Set(password).size;
    if (uniqueChars > 8) strength += 10;

    return {
        score: Math.min(strength, 100),
        level: strength < 40 ? 'Débil' : strength < 70 ? 'Media' : strength < 90 ? 'Fuerte' : 'Muy Fuerte',
        color: strength < 40 ? '#f56565' : strength < 70 ? '#ed8936' : strength < 90 ? '#48bb78' : '#38a169'
    };
}

function checkPasswordExpiration(lastChangedDate) {
    if (!passwordPolicies.expiration.enabled) {
        return { expired: false };
    }

    const now = new Date();
    const lastChanged = new Date(lastChangedDate);
    const daysSinceChange = Math.floor((now - lastChanged) / (1000 * 60 * 60 * 24));
    const daysUntilExpiration = passwordPolicies.expiration.maxAge - daysSinceChange;

    return {
        expired: daysSinceChange >= passwordPolicies.expiration.maxAge,
        daysUntilExpiration: daysUntilExpiration,
        shouldWarn: daysUntilExpiration <= passwordPolicies.expiration.warningDays && daysUntilExpiration > 0,
        daysSinceChange: daysSinceChange
    };
}

async function checkPasswordHistory(userId, newPassword) {
    if (!passwordPolicies.history.enabled) {
        return { isReused: false };
    }

    // Esta función debería consultar el histórico en la base de datos
    // Por ahora retornamos false
    return { isReused: false };
}

// ========================================
// EXPRESIÓN REGULAR PARA VALIDACIÓN
// ========================================
function getPasswordRegex() {
    const p = passwordPolicies.complexity;
    let pattern = '^';
    
    if (p.requireUppercase) pattern += '(?=.*[A-Z])';
    if (p.requireLowercase) pattern += '(?=.*[a-z])';
    if (p.requireNumbers) pattern += '(?=.*\\d)';
    if (p.requireSpecialChars) {
        const escaped = p.specialChars.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
        pattern += `(?=.*[${escaped}])`;
    }
    
    pattern += `.{${p.minLength},${p.maxLength}}$`;
    
    return new RegExp(pattern);
}

// ========================================
// GENERAR CONTRASEÑA SEGURA
// ========================================
function generateSecurePassword(length = 12) {
    const p = passwordPolicies.complexity;
    
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const specials = p.specialChars;
    
    let password = '';
    
    // Asegurar al menos uno de cada tipo requerido
    if (p.requireUppercase) password += uppercase[Math.floor(Math.random() * uppercase.length)];
    if (p.requireLowercase) password += lowercase[Math.floor(Math.random() * lowercase.length)];
    if (p.requireNumbers) password += numbers[Math.floor(Math.random() * numbers.length)];
    if (p.requireSpecialChars) password += specials[Math.floor(Math.random() * specials.length)];
    
    // Completar con caracteres aleatorios
    const allChars = uppercase + lowercase + numbers + specials;
    while (password.length < length) {
        password += allChars[Math.floor(Math.random() * allChars.length)];
    }
    
    // Mezclar
    return password.split('').sort(() => Math.random() - 0.5).join('');
}

// ========================================
// EXPORTAR
// ========================================
module.exports = {
    passwordPolicies,
    validatePasswordComplexity,
    calculatePasswordStrength,
    checkPasswordExpiration,
    checkPasswordHistory,
    getPasswordRegex,
    generateSecurePassword
};
