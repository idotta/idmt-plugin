// API Client for IDMT Plugin

let currentAccessToken = null;
let currentRefreshToken = null;

// Utility function to get the base URL
function getBaseUrl() {
    return window.location.origin;
}

// Utility function to get tenant ID from input
function getTenantId() {
    return document.getElementById('tenantId').value || 'tenant1';
}

// Utility function to get authentication mode
function getAuthMode() {
    return document.getElementById('authMode').value;
}

// Utility function to create headers
function createHeaders(includeAuth = true) {
    const headers = {
        'Content-Type': 'application/json'
    };
    
    // Add tenant header
    const tenantId = getTenantId();
    if (tenantId) {
        headers['__tenant__'] = tenantId;
    }
    
    // Add authorization if needed
    if (includeAuth && currentAccessToken && getAuthMode() === 'bearer') {
        headers['Authorization'] = `Bearer ${currentAccessToken}`;
    }
    
    return headers;
}

// Utility function to display response
function displayResponse(status, statusText, data, error = null) {
    const responseArea = document.getElementById('responseArea');
    
    let html = '';
    
    if (error) {
        html += `<div class="response-error">ERROR: ${error}</div>`;
    }
    
    html += `<div class="response-${status >= 200 && status < 300 ? 'success' : 'error'}">`;
    html += `<strong>Status:</strong> ${status} ${statusText}`;
    html += `<span class="status-badge status-${status >= 200 && status < 300 ? 'success' : 'error'}">${status}</span>`;
    html += `</div>`;
    
    if (data) {
        html += `<div class="response-data">${JSON.stringify(data, null, 2)}</div>`;
    }
    
    responseArea.innerHTML = html;
}

// Utility function to show loading
function showLoading() {
    const responseArea = document.getElementById('responseArea');
    responseArea.innerHTML = '<div class="loading"></div>';
}

// Utility function to make API requests
async function apiRequest(endpoint, options = {}) {
    showLoading();
    
    try {
        const url = `${getBaseUrl()}${endpoint}`;
        const response = await fetch(url, {
            ...options,
            credentials: 'include', // Include cookies
            headers: {
                ...createHeaders(options.includeAuth !== false),
                ...options.headers
            }
        });
        
        let data = null;
        const contentType = response.headers.get('content-type');
        
        if (contentType && contentType.includes('application/json')) {
            data = await response.json();
        } else {
            const text = await response.text();
            if (text) {
                data = { response: text };
            }
        }
        
        displayResponse(response.status, response.statusText, data);
        return { response, data };
    } catch (error) {
        console.error('API Request Error:', error);
        displayResponse(0, 'Network Error', null, error.message);
        throw error;
    }
}

// Update token display
function updateTokenDisplay() {
    const tokenInput = document.getElementById('currentToken');
    if (currentAccessToken) {
        tokenInput.value = currentAccessToken.substring(0, 50) + '...';
    } else {
        tokenInput.value = 'No token';
    }
}

// Clear token
function clearToken() {
    currentAccessToken = null;
    currentRefreshToken = null;
    updateTokenDisplay();
    displayResponse(200, 'OK', { message: 'Token cleared' });
}

// ============================================
// Authentication Endpoints
// ============================================

async function login() {
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    const rememberMe = document.getElementById('loginRememberMe').checked;
    
    const result = await apiRequest('/auth/login', {
        method: 'POST',
        includeAuth: false,
        body: JSON.stringify({ email, password, rememberMe })
    });
    
    if (result.data && result.data.userId) {
        displayResponse(result.response.status, result.response.statusText, {
            ...result.data,
            message: 'Login successful! Cookie has been set.'
        });
    }
}

async function getToken() {
    const email = document.getElementById('tokenEmail').value;
    const password = document.getElementById('tokenPassword').value;
    
    const result = await apiRequest('/auth/token', {
        method: 'POST',
        includeAuth: false,
        body: JSON.stringify({ email, password })
    });
    
    if (result.data && result.data.accessToken) {
        currentAccessToken = result.data.accessToken;
        currentRefreshToken = result.data.refreshToken;
        updateTokenDisplay();
        
        // Update refresh token input
        document.getElementById('refreshToken').value = currentRefreshToken;
    }
}

async function logout() {
    await apiRequest('/auth/logout', {
        method: 'POST'
    });
    
    currentAccessToken = null;
    currentRefreshToken = null;
    updateTokenDisplay();
}

async function refreshToken() {
    const refreshTokenValue = document.getElementById('refreshToken').value || currentRefreshToken;
    
    if (!refreshTokenValue) {
        displayResponse(400, 'Bad Request', null, 'No refresh token provided');
        return;
    }
    
    const result = await apiRequest('/auth/refresh', {
        method: 'POST',
        body: JSON.stringify({ refreshToken: refreshTokenValue })
    });
    
    if (result.data && result.data.accessToken) {
        currentAccessToken = result.data.accessToken;
        currentRefreshToken = result.data.refreshToken;
        updateTokenDisplay();
        
        // Update refresh token input
        document.getElementById('refreshToken').value = currentRefreshToken;
    }
}

async function forgotPassword() {
    const email = document.getElementById('forgotEmail').value;
    const useApiLinks = document.getElementById('forgotUseApiLinks').checked;
    
    await apiRequest(`/auth/forgotPassword?useApiLinks=${useApiLinks}`, {
        method: 'POST',
        includeAuth: false,
        body: JSON.stringify({ email })
    });
}

async function resetPassword() {
    const email = document.getElementById('resetEmail').value;
    const token = document.getElementById('resetToken').value;
    const newPassword = document.getElementById('resetNewPassword').value;
    const tenantId = getTenantId();
    
    await apiRequest(`/auth/resetPassword?tenantIdentifier=${encodeURIComponent(tenantId)}&email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`, {
        method: 'POST',
        includeAuth: false,
        body: JSON.stringify({ newPassword })
    });
}

async function confirmEmail() {
    const email = document.getElementById('confirmEmail').value;
    const token = document.getElementById('confirmToken').value;
    const tenantId = getTenantId();
    
    await apiRequest(`/auth/confirmEmail?tenantIdentifier=${encodeURIComponent(tenantId)}&email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`, {
        method: 'GET',
        includeAuth: false
    });
}

async function resendConfirmationEmail() {
    const email = document.getElementById('resendEmail').value;
    const useApiLinks = document.getElementById('resendUseApiLinks').checked;
    
    await apiRequest(`/auth/resendConfirmationEmail?useApiLinks=${useApiLinks}`, {
        method: 'POST',
        includeAuth: false,
        body: JSON.stringify({ email })
    });
}

// ============================================
// User Management Endpoints
// ============================================

async function getManageInfo() {
    await apiRequest('/manage/info', {
        method: 'GET'
    });
}

async function updateManageInfo() {
    const username = document.getElementById('updateUsername').value;
    const email = document.getElementById('updateEmail').value;
    const phoneNumber = document.getElementById('updatePhoneNumber').value;
    
    const body = {};
    if (username) body.username = username;
    if (email) body.email = email;
    if (phoneNumber) body.phoneNumber = phoneNumber;
    
    await apiRequest('/manage/info', {
        method: 'PUT',
        body: JSON.stringify(body)
    });
}

async function registerUser() {
    const email = document.getElementById('registerEmail').value;
    const username = document.getElementById('registerUsername').value;
    const role = document.getElementById('registerRole').value;
    const useApiLinks = document.getElementById('registerUseApiLinks').checked;
    
    const result = await apiRequest(`/manage/users?useApiLinks=${useApiLinks}`, {
        method: 'POST',
        body: JSON.stringify({ email, username, role })
    });
    
    // If we get a password setup token, display it prominently
    if (result.data && result.data.passwordSetupToken) {
        displayResponse(result.response.status, result.response.statusText, {
            ...result.data,
            note: 'Save the passwordSetupToken to set the user password via /auth/resetPassword'
        });
    }
}

async function updateUser() {
    const userId = document.getElementById('updateUserId').value;
    const isActive = document.getElementById('updateUserActive').checked;
    
    await apiRequest(`/manage/users/${encodeURIComponent(userId)}`, {
        method: 'PUT',
        body: JSON.stringify({ isActive })
    });
}

async function deleteUser() {
    const userId = document.getElementById('deleteUserId').value;
    
    if (!confirm(`Are you sure you want to delete user ${userId}?`)) {
        return;
    }
    
    await apiRequest(`/manage/users/${encodeURIComponent(userId)}`, {
        method: 'DELETE'
    });
}

// ============================================
// System Endpoints
// ============================================

async function getSystemInfo() {
    await apiRequest('/sys/info', {
        method: 'GET'
    });
}

async function healthCheck() {
    await apiRequest('/healthz', {
        method: 'GET'
    });
}

async function createTenant() {
    const identifier = document.getElementById('createTenantIdentifier').value;
    const name = document.getElementById('createTenantName').value;
    const displayName = document.getElementById('createTenantDisplayName').value;
    
    const body = {
        identifier,
        name: name || identifier
    };
    
    if (displayName) {
        body.displayName = displayName;
    }
    
    await apiRequest('/sys/tenants', {
        method: 'POST',
        body: JSON.stringify(body)
    });
}

async function deleteTenant() {
    const tenantIdentifier = document.getElementById('deleteTenantIdentifier').value;
    
    if (!confirm(`Are you sure you want to delete tenant ${tenantIdentifier}? This action cannot be undone.`)) {
        return;
    }
    
    await apiRequest(`/sys/tenants/${encodeURIComponent(tenantIdentifier)}`, {
        method: 'DELETE'
    });
}

async function getUserTenants() {
    const userId = document.getElementById('userTenantsId').value;
    
    await apiRequest(`/sys/users/${encodeURIComponent(userId)}/tenants`, {
        method: 'GET'
    });
}

async function grantTenantAccess() {
    const userId = document.getElementById('grantUserId').value;
    const tenantIdentifier = document.getElementById('grantTenantIdentifier').value;
    const expiresAt = document.getElementById('grantExpiresAt').value;
    
    const body = {
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null
    };
    
    await apiRequest(`/sys/users/${encodeURIComponent(userId)}/tenants/${encodeURIComponent(tenantIdentifier)}`, {
        method: 'POST',
        body: JSON.stringify(body)
    });
}

async function revokeTenantAccess() {
    const userId = document.getElementById('revokeUserId').value;
    const tenantIdentifier = document.getElementById('revokeTenantIdentifier').value;
    
    if (!confirm(`Are you sure you want to revoke access for user ${userId} to tenant ${tenantIdentifier}?`)) {
        return;
    }
    
    await apiRequest(`/sys/users/${encodeURIComponent(userId)}/tenants/${encodeURIComponent(tenantIdentifier)}`, {
        method: 'DELETE'
    });
}

// ============================================
// Initialization
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    updateTokenDisplay();
    displayResponse(200, 'Ready', { message: 'Client initialized and ready to test API endpoints' });
});
