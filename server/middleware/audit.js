const AuditLog = require('../models/AuditLog');

// Middleware to log all requests
const auditLogger = (req, res, next) => {
  // Store original send function
  const originalSend = res.send;
  
  // Store request start time
  req.startTime = Date.now();
  
  // Override send function to capture response
  res.send = function(data) {
    // Only log if user is authenticated (skip public endpoints)
    if (req.user) {
      const responseTime = Date.now() - req.startTime;
      
      // Determine action based on method and path
      let action = 'unknown';
      let resource = 'unknown';
      
      // Map HTTP methods and paths to audit actions
      if (req.path.includes('/auth/login')) {
        action = 'login';
        resource = 'auth';
      } else if (req.path.includes('/auth/logout')) {
        action = 'logout';
        resource = 'auth';
      } else if (req.path.includes('/financial-data')) {
        resource = 'financial_data';
        if (req.method === 'GET') action = 'data_read';
        else if (req.method === 'POST') action = 'data_created';
        else if (req.method === 'PUT' || req.method === 'PATCH') action = 'data_updated';
        else if (req.method === 'DELETE') action = 'data_deleted';
      } else if (req.path.includes('/reports')) {
        resource = 'reports';
        if (req.path.includes('/export')) action = 'report_exported';
        else if (req.method === 'GET') action = 'report_generated';
        else if (req.method === 'POST') action = 'report_created';
      } else if (req.path.includes('/audit')) {
        resource = 'audit';
        action = 'audit_accessed';
      } else if (req.path.includes('/users')) {
        resource = 'users';
        if (req.method === 'GET') action = 'user_read';
        else if (req.method === 'POST') action = 'user_created';
        else if (req.method === 'PUT' || req.method === 'PATCH') action = 'user_updated';
        else if (req.method === 'DELETE') action = 'user_deleted';
      }
      
      // Determine status based on response code
      let status = 'success';
      if (res.statusCode >= 400 && res.statusCode < 500) {
        status = 'warning';
      } else if (res.statusCode >= 500) {
        status = 'failure';
      }
      
      // Log the action
      AuditLog.createLog({
        userId: req.user._id,
        username: req.user.username,
        action: action,
        resource: resource,
        resourceId: req.params.id || null,
        details: {
          method: req.method,
          path: req.path,
          query: req.query,
          body: sanitizeBody(req.body),
          responseCode: res.statusCode,
          responseTime: responseTime,
          userAgent: req.get('User-Agent') || 'unknown'
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: req.user.department,
        role: req.user.role,
        sessionId: req.sessionID || generateSessionId(req),
        status: status
      }).catch(err => {
        console.error('Audit logging error:', err);
      });
    }
    
    return originalSend.call(this, data);
  };
  
  next();
};

// Middleware specifically for data modifications
const auditDataModification = (req, res, next) => {
  // Store original data for before/after comparison
  if (req.method === 'PUT' || req.method === 'PATCH') {
    // This would be set by the route handler with the original data
    req.auditBefore = null;
  }
  
  // Store original send function
  const originalSend = res.send;
  
  res.send = function(data) {
    if (req.user && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      let parsedData = data;
      try {
        if (typeof data === 'string') {
          parsedData = JSON.parse(data);
        }
      } catch (e) {
        // Data is not JSON, use as is
      }
      
      AuditLog.createLog({
        userId: req.user._id,
        username: req.user.username,
        action: getDataAction(req.method),
        resource: 'financial_data',
        resourceId: req.params.id || (parsedData && parsedData._id),
        details: {
          changes: req.body,
          endpoint: req.path
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: req.user.department,
        role: req.user.role,
        sessionId: req.sessionID || generateSessionId(req),
        beforeValue: req.auditBefore || null,
        afterValue: parsedData || null,
        complianceFlags: ['financial_reporting', 'sox']
      }).catch(err => {
        console.error('Data modification audit error:', err);
      });
    }
    
    return originalSend.call(this, data);
  };
  
  next();
};

// Middleware for high-value transactions
const auditHighValueTransaction = (threshold = 50000) => {
  return (req, res, next) => {
    const amount = req.body.budgetAmount || req.body.actualAmount || 0;
    
    if (amount >= threshold) {
      AuditLog.createLog({
        userId: req.user._id,
        username: req.user.username,
        action: 'high_value_transaction',
        resource: 'financial_data',
        details: {
          amount: amount,
          threshold: threshold,
          department: req.body.department,
          category: req.body.category,
          description: req.body.description
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: req.user.department,
        role: req.user.role,
        sessionId: req.sessionID || generateSessionId(req),
        severity: 'high',
        complianceFlags: ['financial_reporting', 'sox'],
        requiresReview: true
      }).catch(err => {
        console.error('High value transaction audit error:', err);
      });
    }
    
    next();
  };
};

// Middleware for bulk operations
const auditBulkOperation = (req, res, next) => {
  const isBulkOperation = req.body && Array.isArray(req.body) && req.body.length > 1;
  
  if (isBulkOperation && req.user) {
    AuditLog.createLog({
      userId: req.user._id,
      username: req.user.username,
      action: req.method === 'POST' ? 'bulk_import' : 'bulk_export',
      resource: 'financial_data',
      details: {
        recordCount: req.body.length,
        operation: req.method,
        endpoint: req.path
      },
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent') || 'unknown',
      department: req.user.department,
      role: req.user.role,
      sessionId: req.sessionID || generateSessionId(req),
      severity: 'medium',
      complianceFlags: ['financial_reporting', 'data_retention']
    }).catch(err => {
      console.error('Bulk operation audit error:', err);
    });
  }
  
  next();
};

// Helper functions
function sanitizeBody(body) {
  if (!body) return {};
  
  const sanitized = { ...body };
  
  // Remove sensitive fields
  const sensitiveFields = ['password', 'mfaSecret', 'token'];
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });
  
  return sanitized;
}

function getDataAction(method) {
  switch (method) {
    case 'POST': return 'data_created';
    case 'PUT':
    case 'PATCH': return 'data_updated';
    case 'DELETE': return 'data_deleted';
    default: return 'data_accessed';
  }
}

function generateSessionId(req) {
  return req.sessionID || 
         req.get('x-session-id') || 
         `${req.ip}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

module.exports = {
  auditLogger,
  auditDataModification,
  auditHighValueTransaction,
  auditBulkOperation
};