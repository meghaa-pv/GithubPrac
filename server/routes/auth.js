const express = require('express');
const bcrypt = require('bcryptjs');
const qrcode = require('qrcode');
const router = express.Router();
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { 
  authenticate, 
  verifyMFA, 
  generateToken, 
  generateMFASecret, 
  verifyMFASetup 
} = require('../middleware/auth');
const { validateRegistration, validateLogin } = require('../utils/validation');

// @route   POST /api/auth/register
// @desc    Register new user
// @access  Public (admin only in production)
router.post('/register', async (req, res) => {
  try {
    const { error } = validateRegistration(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { username, email, password, firstName, lastName, role, department } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({ 
        error: 'User already exists with this email or username' 
      });
    }

    // Create new user
    const user = new User({
      username,
      email,
      password,
      firstName,
      lastName,
      role: role || 'analyst',
      department,
      permissions: User.getRolePermissions(role || 'analyst')
    });

    await user.save();

    // Log user creation
    await AuditLog.createLog({
      userId: user._id,
      username: user.username,
      action: 'user_created',
      resource: 'users',
      resourceId: user._id.toString(),
      details: { role, department },
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent') || 'unknown',
      department: department,
      role: role || 'analyst',
      sessionId: 'registration',
      complianceFlags: ['access_control']
    });

    const token = generateToken(user._id);

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        department: user.department,
        mfaEnabled: user.mfaEnabled
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// @route   POST /api/auth/login
// @desc    Login user
// @access  Public
router.post('/login', async (req, res) => {
  try {
    const { error } = validateLogin(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { email, password, mfaToken } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      await AuditLog.createLog({
        userId: null,
        username: email,
        action: 'login_failed',
        resource: 'auth',
        details: { reason: 'user_not_found' },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: 'unknown',
        role: 'unknown',
        sessionId: 'login_attempt',
        severity: 'medium',
        status: 'failure'
      });
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is locked
    if (user.isLocked) {
      await AuditLog.createLog({
        userId: user._id,
        username: user.username,
        action: 'login_failed',
        resource: 'auth',
        details: { reason: 'account_locked' },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: user.department,
        role: user.role,
        sessionId: 'login_attempt',
        severity: 'medium',
        status: 'failure'
      });
      
      return res.status(401).json({ 
        error: 'Account is locked due to multiple failed attempts' 
      });
    }

    // Check if account is active
    if (!user.isActive) {
      await AuditLog.createLog({
        userId: user._id,
        username: user.username,
        action: 'login_failed',
        resource: 'auth',
        details: { reason: 'account_inactive' },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: user.department,
        role: user.role,
        sessionId: 'login_attempt',
        severity: 'medium',
        status: 'failure'
      });
      
      return res.status(401).json({ error: 'Account is inactive' });
    }

    // Check password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      await user.incLoginAttempts();
      
      await AuditLog.createLog({
        userId: user._id,
        username: user.username,
        action: 'login_failed',
        resource: 'auth',
        details: { reason: 'invalid_password' },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: user.department,
        role: user.role,
        sessionId: 'login_attempt',
        severity: 'medium',
        status: 'failure'
      });
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check MFA if enabled
    if (user.mfaEnabled) {
      if (!mfaToken) {
        return res.status(200).json({ 
          requiresMFA: true,
          message: 'MFA token required'
        });
      }

      const verified = require('speakeasy').totp.verify({
        secret: user.mfaSecret,
        encoding: 'base32',
        token: mfaToken,
        window: 2
      });

      if (!verified) {
        await AuditLog.createLog({
          userId: user._id,
          username: user.username,
          action: 'login_failed',
          resource: 'auth',
          details: { reason: 'invalid_mfa_token' },
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.get('User-Agent') || 'unknown',
          department: user.department,
          role: user.role,
          sessionId: 'login_attempt',
          severity: 'medium',
          status: 'failure'
        });
        
        return res.status(401).json({ error: 'Invalid MFA token' });
      }
    }

    // Reset login attempts on successful login
    if (user.loginAttempts > 0) {
      await user.updateOne({
        $unset: { loginAttempts: 1, lockUntil: 1 }
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate token
    const token = generateToken(user._id);

    // Log successful login
    await AuditLog.createLog({
      userId: user._id,
      username: user.username,
      action: 'login',
      resource: 'auth',
      details: { 
        loginMethod: user.mfaEnabled ? 'password_mfa' : 'password_only' 
      },
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent') || 'unknown',
      department: user.department,
      role: user.role,
      sessionId: token.substring(0, 10),
      complianceFlags: ['access_control']
    });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        department: user.department,
        mfaEnabled: user.mfaEnabled,
        lastLogin: user.lastLogin,
        permissions: user.permissions
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// @route   POST /api/auth/logout
// @desc    Logout user
// @access  Private
router.post('/logout', authenticate, async (req, res) => {
  try {
    // Log logout
    await AuditLog.createLog({
      userId: req.user._id,
      username: req.user.username,
      action: 'logout',
      resource: 'auth',
      details: {},
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent') || 'unknown',
      department: req.user.department,
      role: req.user.role,
      sessionId: req.token.substring(0, 10),
      complianceFlags: ['access_control']
    });

    res.json({ message: 'Logout successful' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// @route   POST /api/auth/setup-mfa
// @desc    Setup MFA for user
// @access  Private
router.post('/setup-mfa', authenticate, async (req, res) => {
  try {
    if (req.user.mfaEnabled) {
      return res.status(400).json({ error: 'MFA is already enabled' });
    }

    const { secret, qrCodeUrl } = generateMFASecret(req.user);

    res.json({
      secret,
      qrCode: qrCodeUrl,
      manualEntryKey: secret
    });
  } catch (error) {
    console.error('MFA setup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// @route   POST /api/auth/verify-mfa
// @desc    Verify and enable MFA
// @access  Private
router.post('/verify-mfa', authenticate, async (req, res) => {
  try {
    const { secret, token } = req.body;

    if (!secret || !token) {
      return res.status(400).json({ error: 'Secret and token are required' });
    }

    const verified = verifyMFASetup(secret, token);
    if (!verified) {
      return res.status(400).json({ error: 'Invalid token' });
    }

    // Enable MFA for user
    req.user.mfaEnabled = true;
    req.user.mfaSecret = secret;
    await req.user.save();

    // Log MFA enablement
    await AuditLog.createLog({
      userId: req.user._id,
      username: req.user.username,
      action: 'mfa_enabled',
      resource: 'auth',
      details: {},
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent') || 'unknown',
      department: req.user.department,
      role: req.user.role,
      sessionId: req.token.substring(0, 10),
      complianceFlags: ['access_control']
    });

    res.json({ message: 'MFA enabled successfully' });
  } catch (error) {
    console.error('MFA verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// @route   POST /api/auth/disable-mfa
// @desc    Disable MFA for user
// @access  Private
router.post('/disable-mfa', authenticate, async (req, res) => {
  try {
    const { password, mfaToken } = req.body;

    if (!password || !mfaToken) {
      return res.status(400).json({ 
        error: 'Password and MFA token are required' 
      });
    }

    // Verify password
    const isPasswordValid = await req.user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Verify MFA token
    const verified = require('speakeasy').totp.verify({
      secret: req.user.mfaSecret,
      encoding: 'base32',
      token: mfaToken,
      window: 2
    });

    if (!verified) {
      return res.status(401).json({ error: 'Invalid MFA token' });
    }

    // Disable MFA
    req.user.mfaEnabled = false;
    req.user.mfaSecret = null;
    await req.user.save();

    // Log MFA disablement
    await AuditLog.createLog({
      userId: req.user._id,
      username: req.user.username,
      action: 'mfa_disabled',
      resource: 'auth',
      details: {},
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent') || 'unknown',
      department: req.user.department,
      role: req.user.role,
      sessionId: req.token.substring(0, 10),
      severity: 'medium',
      complianceFlags: ['access_control']
    });

    res.json({ message: 'MFA disabled successfully' });
  } catch (error) {
    console.error('MFA disable error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// @route   GET /api/auth/me
// @desc    Get current user info
// @access  Private
router.get('/me', authenticate, (req, res) => {
  res.json({
    user: {
      id: req.user._id,
      username: req.user.username,
      email: req.user.email,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      role: req.user.role,
      department: req.user.department,
      mfaEnabled: req.user.mfaEnabled,
      lastLogin: req.user.lastLogin,
      permissions: req.user.permissions,
      reportPreferences: req.user.reportPreferences
    }
  });
});

module.exports = router;