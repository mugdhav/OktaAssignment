/**
 * SECURE express_oidc_app.js WEB APPLICATION WITH OKTA OIDC SSO INTEGRATION
 * =========================================================================
 * 
 * PURPOSE:
 * This express_oidc_app.js application implements Single Sign-On (SSO) authentication using 
 * Okta's OpenID Connect (OIDC) service with the OAuth 2.0 Authorization Code flow.
 * It allows users to securely log into your web application using their existing
 * organizational credentials managed by Okta.
 * 
 * WHAT IS express_oidc_app.js?
 * express_oidc_app.js is a Node.js web application built with the Express framework that provides
 * a robust set of features for web authentication and SSO integration. It:
 * - Creates HTTP servers and handles routing (GET, POST, PUT, DELETE requests)
 * - Manages middleware (functions that execute during request-response cycle)
 * - Handles templating and static file serving
 * - Provides session management and cookie handling
 * - Offers extensive authentication capabilities using Okta OIDC
 * 
 * HOW THIS APPLICATION WORKS:
 * 1. User visits the application and clicks "Login with SSO"
 * 2. Application redirects user to Okta's authorization server
 * 3. User authenticates with Okta using their credentials
 * 4. Okta redirects back with an authorization code
 * 5. Application exchanges the code for access and ID tokens
 * 6. User information is extracted and stored in session
 * 7. User gains access to protected resources
 * 
 * SECURITY FEATURES IMPLEMENTED:
 * - CSRF protection using state parameter validation
 * - Secure session configuration with HTTP-only cookies
 * - Input validation and sanitization
 * - Environment variable protection for secrets
 * - Proper error handling without information disclosure
 * - Security headers middleware
 * - Rate limiting to prevent abuse
 * - Token validation and secure storage
 */

const express = require('express');
const session = require('express-session');
const helmet = require('helmet'); // Security headers middleware
const rateLimit = require('express-rate-limit'); // Rate limiting
const { Issuer, generators } = require('openid-client');
const crypto = require('crypto');
const validator = require('validator'); // Input validation
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// =============================================================================
// SECURITY MIDDLEWARE CONFIGURATION
// =============================================================================

/**
 * Helmet.js - Sets various HTTP headers to secure the app
 * Protects against common vulnerabilities like XSS, clickjacking, etc.
 */
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles for demo
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false // Disable if using external resources
}));

/**
 * Rate Limiting - Prevents brute force attacks and API abuse
 * Limits each IP to 100 requests per 15 minutes
 */
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false,
});
app.use(limiter);

/**
 * More restrictive rate limiting for authentication endpoints
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 login attempts per windowMs
  message: 'Too many login attempts, please try again later.',
});

// =============================================================================
// EXPRESS MIDDLEWARE CONFIGURATION
// =============================================================================

/**
 * Session Configuration
 * Manages user sessions with secure settings
 */
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  resave: false, // Don't save session if unmodified
  saveUninitialized: false, // Don't create session until something stored
  name: 'sessionId', // Change default session name for security
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true, // Prevent XSS attacks
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax' // CSRF protection
  }
}));

/**
 * Body parsing middleware
 * Parses incoming request bodies with size limits to prevent DoS attacks
 */
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// =============================================================================
// OKTA OIDC CLIENT INITIALIZATION
// =============================================================================

let oktaClient;

/**
 * Initialize Okta OIDC Client
 * Discovers Okta's OIDC configuration and creates authenticated client
 * 
 * @returns {Promise<void>}
 * @throws {Error} If initialization fails
 */
async function initializeOktaClient() {
  try {
    // Validate required environment variables
    const requiredEnvVars = [
      'OKTA_OAUTH2_ISSUER',
      'OKTA_OAUTH2_CLIENT_ID',
      'OKTA_OAUTH2_CLIENT_SECRET',
      'OKTA_OAUTH2_REDIRECT_URI'
    ];

    for (const envVar of requiredEnvVars) {
      if (!process.env[envVar]) {
        throw new Error(`Missing required environment variable: ${envVar}`);
      }
    }

    // Validate Okta issuer URL format
    if (!validator.isURL(process.env.OKTA_OAUTH2_ISSUER, { require_protocol: true })) {
      throw new Error('Invalid OKTA_OAUTH2_ISSUER URL format');
    }

    // Discover Okta's OIDC configuration
    console.log('Discovering Okta OIDC configuration...');
    const oktaIssuer = await Issuer.discover(process.env.OKTA_OAUTH2_ISSUER);
    console.log('✓ Discovered Okta issuer:', oktaIssuer.issuer);

    // Create the OIDC client with security best practices
    oktaClient = new oktaIssuer.Client({
      client_id: process.env.OKTA_OAUTH2_CLIENT_ID,
      client_secret: process.env.OKTA_OAUTH2_CLIENT_SECRET,
      redirect_uris: [process.env.OKTA_OAUTH2_REDIRECT_URI],
      response_types: ['code'], // Only authorization code flow
      token_endpoint_auth_method: 'client_secret_basic' // Secure auth method
    });

    console.log('✓ Okta OIDC client initialized successfully');
  } catch (error) {
    console.error('❌ Failed to initialize Okta OIDC client:', error.message);
    process.exit(1);
  }
}

// =============================================================================
// SECURITY MIDDLEWARE FUNCTIONS
// =============================================================================

/**
 * Authentication Middleware
 * Checks if user is authenticated and redirects to login if not
 * 
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object  
 * @param {Function} next - Next middleware function
 */
function requireAuth(req, res, next) {
  if (req.session && req.session.user && req.session.tokens) {
    // Check if access token is still valid
    const tokenExpiry = req.session.tokens.expires_at;
    if (tokenExpiry && Date.now() < tokenExpiry * 1000) {
      return next();
    } else {
      // Token expired, clear session
      req.session.destroy((err) => {
        if (err) console.error('Session destruction error:', err);
      });
    }
  }
  
  // Store the original URL for redirect after login
  req.session.returnTo = req.originalUrl;
  res.redirect('/login');
}

/**
 * Input Validation Middleware
 * Validates and sanitizes user input to prevent injection attacks
 * 
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Next middleware function
 */
function validateInput(req, res, next) {
  // Sanitize query parameters
  for (const key in req.query) {
    if (typeof req.query[key] === 'string') {
      req.query[key] = validator.escape(req.query[key]);
    }
  }
  
  // Sanitize body parameters  
  for (const key in req.body) {
    if (typeof req.body[key] === 'string') {
      req.body[key] = validator.escape(req.body[key]);
    }
  }
  
  next();
}

// =============================================================================
// ROUTE HANDLERS
// =============================================================================

/**
 * Home Page Route
 * Displays welcome page with login/logout options based on authentication status
 * 
 * GET /
 */
app.get('/', (req, res) => {
  try {
    const user = req.session.user;
    
    // Secure HTML template with proper escaping
    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SSO-Enabled Application</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
          .user-info { background: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0; }
          .btn { display: inline-block; padding: 10px 20px; margin: 10px; text-decoration: none; 
                 background: #007bff; color: white; border-radius: 5px; }
          .btn:hover { background: #0056b3; }
          .btn-secondary { background: #6c757d; }
          .btn-secondary:hover { background: #545b62; }
        </style>
      </head>
      <body>
        <h1>🔐 My SSO-Enabled Application</h1>
        ${user ? `
          <div class="user-info">
            <h2>Welcome, ${validator.escape(user.name || user.preferred_username || 'User')}!</h2>
            <p><strong>Email:</strong> ${validator.escape(user.email || 'Not provided')}</p>
            <p><strong>Last Login:</strong> ${new Date().toLocaleString()}</p>
          </div>
          <a href="/dashboard" class="btn">🎛️ Go to Dashboard</a>
          <a href="/api/profile" class="btn btn-secondary">📋 View Profile API</a>
          <a href="/logout" class="btn btn-secondary">🚪 Logout</a>
        ` : `
          <div class="user-info">
            <p>Please log in to access the application features.</p>
            <p>This application uses <strong>Okta Single Sign-On (SSO)</strong> for secure authentication.</p>
          </div>
          <a href="/login" class="btn">🔑 Login with SSO</a>
        `}
      </body>
      </html>
    `;
    
    res.send(html);
  } catch (error) {
    console.error('Home route error:', error);
    res.status(500).send('Internal server error');
  }
});

/**
 * Login Initiation Route  
 * Redirects user to Okta for authentication with proper security parameters
 * 
 * GET /login
 */
app.get('/login', authLimiter, validateInput, async (req, res) => {
  try {
    if (!oktaClient) {
      throw new Error('Okta client not initialized');
    }

    // Generate cryptographically secure state and nonce
    const state = generators.state(32); // 32 bytes = 256 bits
    const nonce = generators.nonce(32);
    
    // Store security parameters in session for validation
    req.session.state = state;
    req.session.nonce = nonce;

    // Build authorization URL with security best practices
    const authUrl = oktaClient.authorizationUrl({
      scope: 'openid profile email', // Minimal required scopes
      state: state,
      nonce: nonce,
      response_type: 'code',
      // Optional: Add PKCE for additional security
      code_challenge_method: 'S256'
    });

    console.log('🔄 Redirecting user to Okta for authentication');
    res.redirect(authUrl);
    
  } catch (error) {
    console.error('❌ Login initiation error:', error.message);
    res.status(500).send(`
      <h1>Login Error</h1>
      <p>Unable to initiate login process. Please try again later.</p>
      <a href="/">← Back to Home</a>
    `);
  }
});

/**
 * OAuth Callback Route
 * Handles the authorization code returned from Okta and exchanges it for tokens
 * 
 * GET /callback
 */
app.get('/callback', validateInput, async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    // Handle OAuth errors
    if (error) {
      console.error('❌ OAuth error:', error, error_description);
      return res.status(400).send(`
        <h1>Authentication Error</h1>
        <p>Error: ${validator.escape(error)}</p>
        <p>Description: ${validator.escape(error_description || 'Unknown error')}</p>
        <a href="/">← Back to Home</a>
      `);
    }

    // Validate required parameters
    if (!code || !state) {
      console.error('❌ Missing required callback parameters');
      return res.status(400).send(`
        <h1>Invalid Callback</h1>
        <p>Missing required authentication parameters.</p>
        <a href="/">← Back to Home</a>
      `);
    }

    // Validate state parameter (CSRF protection)
    if (state !== req.session.state) {
      console.error('❌ State parameter mismatch - potential CSRF attack');
      return res.status(400).send(`
        <h1>Security Error</h1>
        <p>Invalid state parameter. Please try logging in again.</p>
        <a href="/">← Back to Home</a>
      `);
    }

    console.log('✓ Authorization code received, exchanging for tokens...');

    // Exchange authorization code for tokens
    const tokenSet = await oktaClient.callback(
      process.env.OKTA_OAUTH2_REDIRECT_URI,
      { code, state },
      { 
        state: req.session.state,
        nonce: req.session.nonce 
      }
    );

    console.log('✓ Token exchange successful');

    // Validate ID token and extract user information
    const userInfo = tokenSet.claims();
    
    // Fetch additional user information from /userinfo endpoint
    let additionalUserInfo = {};
    try {
      additionalUserInfo = await oktaClient.userinfo(tokenSet.access_token);
    } catch (userInfoError) {
      console.warn('⚠️ Failed to fetch additional user info:', userInfoError.message);
    }

    const combinedUserInfo = { ...userInfo, ...additionalUserInfo };

    // Store user info and tokens in session with timestamp
    req.session.user = combinedUserInfo;
    req.session.tokens = {
      access_token: tokenSet.access_token,
      id_token: tokenSet.id_token,
      refresh_token: tokenSet.refresh_token,
      expires_at: tokenSet.expires_at,
      authenticated_at: Math.floor(Date.now() / 1000)
    };

    // Clear temporary security parameters
    delete req.session.state;
    delete req.session.nonce;

    console.log('✅ User authenticated successfully:', 
      combinedUserInfo.preferred_username || combinedUserInfo.email);

    // Redirect to originally requested URL or dashboard
    const returnTo = req.session.returnTo || '/dashboard';
    delete req.session.returnTo;
    res.redirect(returnTo);

  } catch (error) {
    console.error('❌ Callback processing error:', error.message);
    res.status(500).send(`
      <h1>Authentication Failed</h1>
      <p>Unable to complete authentication. Please try again.</p>
      <a href="/">← Back to Home</a>
    `);
  }
});

/**
 * Protected Dashboard Route
 * Displays user dashboard with profile information (requires authentication)
 * 
 * GET /dashboard
 */
app.get('/dashboard', requireAuth, (req, res) => {
  try {
    const user = req.session.user;
    const tokens = req.session.tokens;
    
    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard - SSO Application</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 1000px; margin: 20px auto; padding: 20px; }
          .profile-card { background: #f8f9fa; border-radius: 10px; padding: 30px; margin: 20px 0; 
                         box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }
          .info-item { background: white; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff; }
          .btn { display: inline-block; padding: 12px 24px; margin: 10px; text-decoration: none; 
                 background: #007bff; color: white; border-radius: 5px; font-weight: bold; }
          .btn:hover { background: #0056b3; }
          .btn-secondary { background: #6c757d; }
          .session-info { font-size: 0.9em; color: #666; margin-top: 20px; }
        </style>
      </head>
      <body>
        <h1>🎛️ User Dashboard</h1>
        
        <div class="profile-card">
          <h2>Welcome, ${validator.escape(user.name || user.preferred_username || 'User')}!</h2>
          <p>You have successfully authenticated using Okta SSO.</p>
          
          <div class="info-grid">
            <div class="info-item">
              <strong>👤 Full Name:</strong><br>
              ${validator.escape(user.name || 'Not provided')}
            </div>
            <div class="info-item">
              <strong>📧 Email Address:</strong><br>
              ${validator.escape(user.email || 'Not provided')}
            </div>
            <div class="info-item">
              <strong>🏷️ Username:</strong><br>
              ${validator.escape(user.preferred_username || 'Not provided')}
            </div>
            <div class="info-item">
              <strong>👥 Groups:</strong><br>
              ${user.groups ? user.groups.map(g => validator.escape(g)).join(', ') : 'Not provided'}
            </div>
            <div class="info-item">
              <strong>🌐 Locale:</strong><br>
              ${validator.escape(user.locale || 'Not provided')}
            </div>
            <div class="info-item">
              <strong>⏰ Login Time:</strong><br>
              ${new Date(tokens.authenticated_at * 1000).toLocaleString()}
            </div>
          </div>
          
          <div class="session-info">
            <p><strong>Session Information:</strong></p>
            <p>Token expires: ${new Date(tokens.expires_at * 1000).toLocaleString()}</p>
            <p>Session ID: ${req.sessionID.substring(0, 8)}...</p>
          </div>
        </div>
        
        <a href="/" class="btn">🏠 Home</a>
        <a href="/api/profile" class="btn btn-secondary">📋 API Profile</a>
        <a href="/logout" class="btn btn-secondary">🚪 Logout</a>
      </body>
      </html>
    `;
    
    res.send(html);
  } catch (error) {
    console.error('❌ Dashboard error:', error);
    res.status(500).send('Internal server error');
  }
});

/**
 * Logout Route
 * Clears local session and redirects to Okta logout for complete sign-out
 * 
 * GET /logout
 */
app.get('/logout', (req, res) => {
  try {
    const idToken = req.session.tokens?.id_token;
    const user = req.session.user;
    
    console.log('🔄 User logging out:', user?.preferred_username || user?.email || 'Unknown');
    
    // Clear session data
    req.session.destroy((err) => {
      if (err) {
        console.error('❌ Session destruction error:', err);
      }
    });

    // Build Okta logout URL for complete sign-out
    if (idToken && process.env.OKTA_OAUTH2_ISSUER) {
      const postLogoutUri = encodeURIComponent(`${req.protocol}://${req.get('host')}/`);
      const logoutUrl = `${process.env.OKTA_OAUTH2_ISSUER}/v1/logout?` +
        `id_token_hint=${idToken}&` +
        `post_logout_redirect_uri=${postLogoutUri}`;
      
      console.log('✅ Redirecting to Okta logout');
      return res.redirect(logoutUrl);
    } else {
      console.log('✅ Local logout completed');
      return res.redirect('/?logged_out=true');
    }
  } catch (error) {
    console.error('❌ Logout error:', error);
    res.redirect('/');
  }
});

/**
 * Protected API Endpoint
 * Returns user profile data as JSON (requires authentication)
 * 
 * GET /api/profile
 */
app.get('/api/profile', requireAuth, (req, res) => {
  try {
    // Return sanitized user data
    const userData = {
      id: req.session.user.sub,
      name: req.session.user.name,
      email: req.session.user.email,
      username: req.session.user.preferred_username,
      groups: req.session.user.groups || [],
      locale: req.session.user.locale,
      authenticated_at: req.session.tokens.authenticated_at,
      expires_at: req.session.tokens.expires_at
    };

    res.json({
      success: true,
      message: 'Profile data retrieved successfully',
      user: userData,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Profile API error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve profile data',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

/**
 * Health Check Endpoint
 * Returns application health status
 * 
 * GET /health
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

// =============================================================================
// ERROR HANDLING MIDDLEWARE
// =============================================================================

/**
 * 404 Error Handler
 * Handles requests to non-existent routes
 */
app.use((req, res) => {
  res.status(404).send(`
    <h1>404 - Page Not Found</h1>
    <p>The requested page does not exist.</p>
    <a href="/">← Back to Home</a>
  `);
});

/**
 * Global Error Handler
 * Catches and handles all unhandled errors
 */
app.use((error, req, res, next) => {
  console.error('❌ Unhandled application error:', {
    message: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // Don't expose error details in production
  const errorMessage = process.env.NODE_ENV === 'production' 
    ? 'Internal server error' 
    : error.message;

  res.status(error.status || 500).send(`
    <h1>Application Error</h1>
    <p>${errorMessage}</p>
    <a href="/">← Back to Home</a>
  `);
});

// =============================================================================
// SERVER INITIALIZATION
// =============================================================================

/**
 * Initialize and Start Server
 * Performs all necessary setup and starts the Express server
 */
async function startServer() {
  try {
    console.log('🚀 Starting SSO-enabled express_oidc_app.js application...\n');
    
    // Initialize Okta client
    await initializeOktaClient();
    
    // Start Express server
    app.listen(port, () => {
      console.log('\n✅ Server started successfully!');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`🌐 Application URL: http://localhost:${port}`);
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log('\n📋 Configuration:');
      console.log('   • Okta Issuer:', process.env.OKTA_OAUTH2_ISSUER);
      console.log('   • Client ID:', process.env.OKTA_OAUTH2_CLIENT_ID);
      console.log('   • Redirect URI:', process.env.OKTA_OAUTH2_REDIRECT_URI);
      console.log('   • Environment:', process.env.NODE_ENV || 'development');
      console.log('\n🔒 Security Features Enabled:');
      console.log('   • Rate Limiting ✓');
      console.log('   • Security Headers ✓');
      console.log('   • Input Validation ✓');
      console.log('   • CSRF Protection ✓');
      console.log('   • Secure Sessions ✓');
      console.log('\nReady to accept connections! 🎉\n');
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully...');
  process.exit(0);
});

// Start the application
startServer().catch(console.error);