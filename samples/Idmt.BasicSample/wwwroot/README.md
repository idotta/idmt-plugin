# IDMT Plugin API Test Client

An interactive web-based client application for testing and demonstrating all endpoints of the IDMT Plugin API.

## Overview

This client application provides a user-friendly interface to interact with all API endpoints exposed by the BasicSample application, including:
- Authentication endpoints (login, token, logout, password management)
- User management endpoints (profile, user registration, activation)
- System endpoints (system info, health checks, tenant management)

## Features

- **Full API Coverage**: All endpoints documented in the main README are accessible
- **Dual Authentication Modes**: Support for both Bearer Token and Cookie-based authentication
- **Multi-Tenancy Support**: Configure tenant ID via header
- **Real-Time Response Display**: View API responses with formatted JSON and status codes
- **Token Management**: Store, display, and manage access tokens
- **Modern UI**: Responsive design with gradient theme and visual feedback
- **Error Handling**: Clear error messages and validation feedback

## Getting Started

### Running the Application

1. Navigate to the BasicSample directory:
   ```bash
   cd src/samples/Idmt.BasicSample
   ```

2. Run the application:
   ```bash
   dotnet run
   ```

3. Open your browser and navigate to:
   ```
   http://localhost:5172
   ```

### Initial Setup

Since no default users are seeded, you'll need to:

1. **Create Your First User**
   - The application seeds a default tenant: `system-tenant`
   - You cannot register users without authentication, so you need to manually seed a user or modify the seeding logic

2. **Alternative: Using Integration Tests Credentials**
   - For testing purposes, you can seed a test admin user using the test factory pattern
   - See `IdmtApiFactory.cs` in the tests project for an example

## Usage Guide

### Configuration Panel

At the top of the page, you'll find configuration options:

- **Tenant ID**: Set the tenant identifier (default: `system-tenant`)
- **Authentication Mode**: Choose between Bearer Token or Cookie authentication
- **Current Access Token**: Displays your current access token (read-only)
- **Clear Token**: Removes the stored access token

### Authentication Flow

#### Bearer Token Authentication

1. Navigate to **POST /auth/token**
2. Enter email and password
3. Click "Get Token"
4. The access token will be automatically stored and used for subsequent requests

#### Cookie Authentication

1. Navigate to **POST /auth/login**
2. Enter email and password
3. Click "Login"
4. The authentication cookie will be automatically set by the server

### Testing Endpoints

Each endpoint section contains:
- The HTTP method and path
- Input fields for required parameters
- A button to execute the request
- Results displayed in the Response panel

### Multi-Tenancy

The application supports multiple tenant resolution strategies:

- **Header Strategy**: Set via the Tenant ID field in Configuration
- The tenant identifier is automatically included in the `__tenant__` header for all requests

## API Endpoints Reference

### Authentication (`/auth`)

| Endpoint | Description | Auth Required |
|----------|-------------|---------------|
| `POST /auth/login` | Cookie-based login | No |
| `POST /auth/token` | Get bearer token | No |
| `POST /auth/logout` | Logout user | Yes |
| `POST /auth/refresh` | Refresh access token | Yes |
| `POST /auth/forgotPassword` | Request password reset | No |
| `POST /auth/resetPassword` | Reset password with token | No |
| `GET /auth/confirmEmail` | Confirm email address | No |
| `POST /auth/resendConfirmationEmail` | Resend confirmation email | No |

### User Management (`/manage`)

| Endpoint | Description | Auth Required | Policy |
|----------|-------------|---------------|--------|
| `GET /manage/info` | Get current user info | Yes | Authenticated |
| `PUT /manage/info` | Update current user info | Yes | Authenticated |
| `POST /manage/users` | Register new user | Yes | RequireSysUser |
| `PUT /manage/users/{id}` | Update user (activate/deactivate) | Yes | RequireTenantManager |
| `DELETE /manage/users/{id}` | Delete user | Yes | RequireTenantManager |

### System (`/admin`)

| Endpoint | Description | Auth Required | Policy |
|----------|-------------|---------------|--------|
| `GET /admin/info` | Get system information | Yes | Authenticated |
| `GET /healthz` | Health check | Yes | Authenticated |
| `GET /admin/users/{id}/tenants` | List user's tenants | Yes | RequireAdminUser |
| `POST /admin/users/{id}/tenants/{tenantId}` | Grant tenant access | Yes | RequireAdminUser |
| `DELETE /admin/users/{id}/tenants/{tenantId}` | Revoke tenant access | Yes | RequireAdminUser |

## Typical Testing Workflow

1. **Start Fresh**
   - Clear any existing tokens
   - Set the correct tenant ID

2. **Create a User** (requires admin)
   - Use `POST /manage/users` to register a new user
   - Save the `passwordSetupToken` from the response

3. **Set User Password**
   - Use `POST /auth/resetPassword` with the setup token
   - Provide the email, token, and new password

4. **Login**
   - Use `POST /auth/token` or `POST /auth/login`
   - Store the access token if using bearer authentication

5. **Test Protected Endpoints**
   - Try `GET /manage/info` to verify authentication
   - Test other endpoints as needed

6. **Refresh Token** (Bearer only)
   - When the access token expires
   - Use `POST /auth/refresh` with the refresh token

## Tips

- **Response Panel**: The response panel at the top shows the result of your last API call with status code and JSON response
- **Authentication Mode**: Switch between Bearer and Cookie modes to test both authentication strategies
- **Error Messages**: Failed requests will show error details in the response panel
- **Token Expiration**: Bearer tokens expire after 1 hour by default. Use the refresh endpoint to get a new token
- **Tenant Context**: All requests include the tenant header based on your configuration

## Technical Details

### Files

- `wwwroot/index.html` - Main HTML structure and forms
- `wwwroot/css/styles.css` - Styling and layout
- `wwwroot/js/api-client.js` - API client logic and request handling

### JavaScript API

The API client (`api-client.js`) provides:

- `apiRequest(endpoint, options)` - Core request function
- Individual functions for each endpoint (e.g., `login()`, `getToken()`, etc.)
- Token management utilities
- Response formatting and display

### Browser Compatibility

Modern browsers with support for:
- ES6 JavaScript features
- Fetch API
- CSS Grid and Flexbox

## Troubleshooting

### 401 Unauthorized
- Ensure you're logged in (token or cookie is set)
- Check that your token hasn't expired
- Verify you're using the correct tenant ID

### 403 Forbidden
- Your user doesn't have the required role/policy
- Check authorization policies in the API reference

### 404 Not Found
- Verify the endpoint URL is correct
- Ensure the tenant exists and is active

### CORS Issues
- The client is served from the same origin as the API
- No CORS configuration needed

## Development

To modify the client:

1. Edit the HTML/CSS/JS files in `wwwroot/`
2. Refresh your browser (no rebuild needed for static files)
3. Use browser DevTools to debug JavaScript

## License

This client application is part of the IDMT Plugin project and follows the same license.
