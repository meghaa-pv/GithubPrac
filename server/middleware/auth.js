const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

// Generate JWT token
const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE || '7d'
  });
};

// Verify JWT token
const verifyToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      await AuditLog.createLog({
        userId: null,
        username: 'anonymous',
        action: 'unauthorized_access_attempt',
        resource: 'auth',
        details: { endpoint: req.path, method: req.method },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: 'unknown',
        role: 'unknown',
        sessionId: req.sessionID || 'unknown',
        severity: 'high',
        status: 'failure'
      });
      
      return res.status(401).json({ 
        error: 'Access denied. No token provided.' 
      });
    }
    
    const token = authHeader.substring(7);
    const decoded = verifyToken(token);
    
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      await AuditLog.createLog({
        userId: decoded.userId,
        username: 'unknown',
        action: 'unauthorized_access_attempt',
        resource: 'auth',
        details: { reason: 'user_not_found', endpoint: req.path },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: 'unknown',
        role: 'unknown',
        sessionId: req.sessionID || 'unknown',
        severity: 'high',
        status: 'failure'
      });
      
      return res.status(401).json({ 
        error: 'Access denied. User not found.' 
      });
    }
    
    if (!user.isActive) {
      await AuditLog.createLog({
        userId: user._id,
        username: user.username,
        action: 'unauthorized_access_attempt',
        resource: 'auth',
        details: { reason: 'account_inactive', endpoint: req.path },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: user.department,
        role: user.role,
        sessionId: req.sessionID || 'unknown',
        severity: 'medium',
        status: 'failure'
      });
      
      return res.status(401).json({ 
        error: 'Access denied. Account is inactive.' 
      });
    }
    
    if (user.isLocked) {
      await AuditLog.createLog({
        userId: user._id,
        username: user.username,
        action: 'unauthorized_access_attempt',
        resource: 'auth',
        details: { reason: 'account_locked', endpoint: req.path },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: user.department,
        role: user.role,
        sessionId: req.sessionID || 'unknown',
        severity: 'medium',
        status: 'failure'
      });
      
      return res.status(401).json({ 
        error: 'Access denied. Account is locked.' 
      });
    }
    
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      await AuditLog.createLog({
        userId: null,
        username: 'anonymous',
        action: 'unauthorized_access_attempt',
        resource: 'auth',
        details: { 
          reason: 'invalid_token', 
          endpoint: req.path,
          error: error.message 
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: 'unknown',
        role: 'unknown',
        sessionId: req.sessionID || 'unknown',
        severity: 'high',
        status: 'failure'
      });
      
      return res.status(401).json({ 
        error: 'Access denied. Invalid token.' 
      });
    }
    
    console.error('Authentication error:', error);
    res.status(500).json({ 
      error: 'Internal server error during authentication.' 
    });
  }
};

// MFA verification middleware
const verifyMFA = (req, res, next) => {
  if (!req.user.mfaEnabled) {
    return next();
  }
  
  const { mfaToken } = req.body;
  
  if (!mfaToken) {
    return res.status(401).json({ 
      error: 'MFA token required.',
      requiresMFA: true 
    });
  }
  
  const verified = speakeasy.totp.verify({
    secret: req.user.mfaSecret,
    encoding: 'base32',
    token: mfaToken,
    window: 2
  });
  
  if (!verified) {
    AuditLog.createLog({
      userId: req.user._id,
      username: req.user.username,
      action: 'login_failed',
      resource: 'auth',
      details: { reason: 'invalid_mfa_token' },
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent') || 'unknown',
      department: req.user.department,
      role: req.user.role,
      sessionId: req.sessionID || 'unknown',
      severity: 'medium',
      status: 'failure'
    });
    
    return res.status(401).json({ 
      error: 'Invalid MFA token.' 
    });
  }
  
  next();
};

// Generate MFA secret and QR code
const generateMFASecret = (user) => {
  const secret = speakeasy.generateSecret({
    name: `Financial Analytics - ${user.username}`,
    issuer: 'Enterprise Financial Platform',
    length: 32
  });
  
  return {
    secret: secret.base32,
    qrCodeUrl: secret.otpauth_url
  };
};

// Verify MFA setup token
const verifyMFASetup = (secret, token) => {
  return speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 2
  });
};

module.exports = {
  authenticate,
  verifyMFA,
  generateToken,
  verifyToken,
  generateMFASecret,
  verifyMFASetup
};