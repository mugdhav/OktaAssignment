# Express OIDC SSO Integration with Okta

## Overview

This repository contains a secure Express OIDC application that implements **Single Sign-On (SSO)** authentication using **Okta's OpenID Connect (OIDC)** service. The application allows users to authenticate using their existing organizational credentials managed by Okta, providing seamless access across multiple applications.

## Purpose

The Express OIDC application serves as an authentication middleware layer that:

- **Handles OAuth 2.0 Authorization Code Flow** with Okta OIDC
- **Manages user sessions** securely with proper cookie configuration
- **Provides protected routes** that require authentication
- **Implements security best practices** including CSRF protection, rate limiting, and input validation
- **Offers REST API endpoints** for authenticated user data access

## File Structure

### 🚀 **Express OIDC Application (`express_oidc_app.js`)**
The main application file containing:
- **OIDC Authentication Logic** - Login, callback, and logout handling
- **Security Middleware** - Rate limiting, headers, input validation
- **Route Handlers** - Public pages, protected dashboard, API endpoints
- **Session Management** - Secure session configuration and token storage
- **Error Handling** - Comprehensive error management and logging

### 📝 **Environment Configuration (`.env`)**
Contains sensitive configuration data that you must customize with your specific values:

```env
OKTA_OAUTH2_ISSUER=https://your-domain.okta.com/oauth2/default
OKTA_OAUTH2_CLIENT_ID=your_client_id_from_okta
OKTA_OAUTH2_CLIENT_SECRET=your_client_secret_from_okta
OKTA_OAUTH2_REDIRECT_URI=http://localhost:3000/callback
SESSION_SECRET=your_secure_session_secret
NODE_ENV=development
PORT=3000
```

#### **Where to Find These Values:**

| Variable | Replace With | Where to Find It |
|----------|--------------|------------------|
| `OKTA_OAUTH2_ISSUER` | Your actual Okta domain + `/oauth2/default` | **Okta Admin Console** → Upper right corner shows your Okta URL (e.g., `https://dev-123456.okta.com/oauth2/default`) |
| `OKTA_OAUTH2_CLIENT_ID` | Generated Client ID | **Okta Admin Console** → **Applications** → **Your OIDC App** → **General Tab** → **Client Credentials** section |
| `OKTA_OAUTH2_CLIENT_SECRET` | Generated Client Secret | **Okta Admin Console** → **Applications** → **Your OIDC App** → **General Tab** → **Client Credentials** → Click **Show** next to Client Secret |
| `OKTA_OAUTH2_REDIRECT_URI` | Your application's callback URL | Must match the **Sign-in redirect URIs** configured in your Okta app (change port/domain as needed) |
| `SESSION_SECRET` | Random secure string | Generate using: `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"` |
| `NODE_ENV` | Your environment | Use `development` for local testing, `production` for live deployment |
| `PORT` | Your application port | Change if your app runs on a different port |

### 📦 **Package Dependencies (`package.json`)**
Defines required Node.js packages:
- **express** - Web application framework
- **express-session** - Session management middleware
- **openid-client** - OIDC client library for token handling
- **helmet** - Security headers middleware
- **express-rate-limit** - Rate limiting for API protection
- **validator** - Input validation and sanitization
- **dotenv** - Environment variable management

## Integration with Existing Web Applications

### Prerequisites

Before integrating with your existing application:

1. **Okta Configuration**
   - Create an OIDC Web Application in your Okta Admin Console
   - Note down the Client ID, Client Secret, and Issuer URL
   - Configure redirect URIs to match your application URLs

2. **Node.js Environment**
   - Node.js version 16+ installed
   - NPM or Yarn package manager

### Option 1: Standalone Authentication Service

Use the Express OIDC app as a separate authentication microservice:

#### Setup Steps:

1. **Clone and Install**
   ```bash
   git clone <your-repo-url>
   cd <your-repo-name>
   npm install
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your Okta configuration
   ```

3. **Start Authentication Service**
   ```bash
   npm start
   # Service runs on http://localhost:3000
   ```

4. **Integrate with Your Existing App**
   
   **In your existing application:**
   ```javascript
   // Redirect users to authentication service for login
   function redirectToLogin() {
     window.location.href = 'http://localhost:3000/login';
   }
   
   // Check authentication status via API
   async function checkAuth() {
     try {
       const response = await fetch('http://localhost:3000/api/profile', {
         credentials: 'include' // Important for cross-origin cookies
       });
       return response.ok;
     } catch (error) {
       return false;
     }
   }
   ```

### Option 2: Direct Integration

Integrate the authentication code directly into your existing Web application:

#### Integration Steps:

1. **Install Dependencies**
   ```bash
   npm install express-session openid-client helmet express-rate-limit validator dotenv
   ```

2. **Add Environment Variables**
   Add the Okta configuration to your existing `.env` file:
   ```env
   # Add these to your existing .env
   OKTA_OAUTH2_ISSUER=https://your-domain.okta.com/oauth2/default
   OKTA_OAUTH2_CLIENT_ID=your_client_id
   OKTA_OAUTH2_CLIENT_SECRET=your_client_secret
   OKTA_OAUTH2_REDIRECT_URI=http://localhost:YOUR_PORT/callback
   SESSION_SECRET=your_secure_session_secret
   ```

3. **Integrate Authentication Code**
   
   **Add to your main app file:**
   ```javascript
   // Import required modules (add to your existing imports)
   const session = require('express-session');
   const helmet = require('helmet');
   const rateLimit = require('express-rate-limit');
   const { Issuer } = require('openid-client');
   
   // Add security middleware (before your existing routes)
   app.use(helmet());
   app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
   
   // Add session configuration
   app.use(session({
     secret: process.env.SESSION_SECRET,
     resave: false,
     saveUninitialized: false,
     cookie: { 
       secure: process.env.NODE_ENV === 'production',
       httpOnly: true,
       maxAge: 24 * 60 * 60 * 1000
     }
   }));
   
   // Copy the authentication functions and routes from app.js
   // (initializeOktaClient, requireAuth, login routes, etc.)
   ```

4. **Protect Your Existing Routes**
   ```javascript
   // Add authentication to your existing protected routes
   app.get('/your-protected-route', requireAuth, (req, res) => {
     // Your existing route logic
     // Access user info via req.session.user
   });
   ```

## Usage Instructions

### For End Users:

1. **Access Application** - Navigate to your application URL.
2. **Login** - Click "Login with SSO" to authenticate via Okta.
3. **Use Application** - Access protected features after authentication.
4. **Logout** - Click "Logout" to end session and clear tokens.

### For Developers:

#### Accessing User Data:
```javascript
app.get('/your-route', requireAuth, (req, res) => {
  const user = req.session.user;
  console.log('User:', user.name, user.email);
  // Use user data in your application logic
});
```

#### API Integration:
```javascript
// Check if user is authenticated
fetch('/api/profile')
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      console.log('User authenticated:', data.user);
    }
  });
```

## Security Features

- ✅ **CSRF Protection** - State parameter validation
- ✅ **Rate Limiting** - Prevents brute force attacks  
- ✅ **Secure Sessions** - HTTP-only, SameSite cookies
- ✅ **Input Validation** - Sanitizes user input
- ✅ **Security Headers** - Comprehensive header protection
- ✅ **Token Validation** - Checks token expiration
- ✅ **Error Handling** - No information disclosure

## Troubleshooting

### Common Issues:

1. **"Okta client not initialized"**
   - Check your `.env` file configuration.
   - Ensure Okta issuer URL is correct.

2. **"Invalid redirect URI"**
   - Verify redirect URI in Okta matches your application.
   - Check for HTTP vs HTTPS mismatch.

3. **Session issues**
   - Ensure SESSION_SECRET is set.
   - Check cookie settings for your environment.

4. **CORS issues (cross-origin setup)**
   - Configure CORS middleware if using separate services.
   - Set `credentials: 'include'` in fetch requests.

### Debug Mode:
```bash
DEBUG=express:* NODE_ENV=development npm start
```

## Support

For issues related to:
- **Okta Configuration** - Check [Okta Developer Documentation](https://developer.okta.com).
- **Express OIDC Integration** - Review the application logs.
- **Authentication Flow** - Enable debug mode for detailed logging.

