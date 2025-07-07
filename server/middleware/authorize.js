const AuditLog = require('../models/AuditLog');

// Check if user has required role
const requireRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    
    if (!allowedRoles.includes(req.user.role)) {
      AuditLog.createLog({
        userId: req.user._id,
        username: req.user.username,
        action: 'unauthorized_access_attempt',
        resource: req.baseUrl || 'unknown',
        details: { 
          requiredRoles: allowedRoles,
          userRole: req.user.role,
          endpoint: req.path 
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: req.user.department,
        role: req.user.role,
        sessionId: req.sessionID || 'unknown',
        severity: 'medium',
        status: 'failure'
      });
      
      return res.status(403).json({ 
        error: 'Insufficient privileges. Required roles: ' + allowedRoles.join(', ') 
      });
    }
    
    next();
  };
};

// Check if user has required permission for specific resource and action
const requirePermission = (resource, action) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    
    const hasPermission = req.user.hasPermission(resource, action);
    
    if (!hasPermission) {
      AuditLog.createLog({
        userId: req.user._id,
        username: req.user.username,
        action: 'unauthorized_access_attempt',
        resource: resource,
        details: { 
          requiredPermission: { resource, action },
          endpoint: req.path,
          method: req.method
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: req.user.department,
        role: req.user.role,
        sessionId: req.sessionID || 'unknown',
        severity: 'medium',
        status: 'failure'
      });
      
      return res.status(403).json({ 
        error: `Insufficient privileges. Required permission: ${action} on ${resource}` 
      });
    }
    
    next();
  };
};

// Check if user can access specific department data
const requireDepartmentAccess = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  
  const requestedDepartment = req.params.department || req.query.department || req.body.department;
  
  // Executives and finance can access all departments
  if (['executive', 'finance'].includes(req.user.role)) {
    return next();
  }
  
  // Users can only access their own department data
  if (requestedDepartment && requestedDepartment !== req.user.department) {
    AuditLog.createLog({
      userId: req.user._id,
      username: req.user.username,
      action: 'unauthorized_access_attempt',
      resource: 'financial_data',
      details: { 
        requestedDepartment,
        userDepartment: req.user.department,
        endpoint: req.path 
      },
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent') || 'unknown',
      department: req.user.department,
      role: req.user.role,
      sessionId: req.sessionID || 'unknown',
      severity: 'medium',
      status: 'failure'
    });
    
    return res.status(403).json({ 
      error: 'Access denied. Cannot access other department data.' 
    });
  }
  
  next();
};

// Check if user can modify financial data (approval workflow)
const requireApproval = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  
  const amount = req.body.budgetAmount || req.body.actualAmount || 0;
  const approvalThresholds = {
    analyst: 1000,
    manager: 10000,
    finance: 100000,
    executive: Infinity
  };
  
  const userThreshold = approvalThresholds[req.user.role] || 0;
  
  if (amount > userThreshold) {
    return res.status(403).json({ 
      error: `Amount exceeds approval threshold. Maximum allowed: $${userThreshold.toLocaleString()}`,
      requiresApproval: true,
      threshold: userThreshold
    });
  }
  
  next();
};

// Middleware to filter data based on user permissions
const filterDataByPermissions = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  
  // Store original send function
  const originalSend = res.send;
  
  // Override send function to filter data
  res.send = function(data) {
    if (typeof data === 'string') {
      try {
        data = JSON.parse(data);
      } catch (e) {
        return originalSend.call(this, data);
      }
    }
    
    if (data && Array.isArray(data)) {
      // Filter array of financial data based on department access
      if (!['executive', 'finance'].includes(req.user.role)) {
        data = data.filter(item => 
          !item.department || item.department === req.user.department
        );
      }
    } else if (data && typeof data === 'object' && data.department) {
      // Filter single object
      if (!['executive', 'finance'].includes(req.user.role) && 
          data.department !== req.user.department) {
        return res.status(403).json({ 
          error: 'Access denied to this department data.' 
        });
      }
    }
    
    return originalSend.call(this, JSON.stringify(data));
  };
  
  next();
};

// Middleware to check if user can export sensitive data
const requireExportPermission = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  
  const sensitiveRoles = ['executive', 'finance', 'manager'];
  
  if (!sensitiveRoles.includes(req.user.role)) {
    AuditLog.createLog({
      userId: req.user._id,
      username: req.user.username,
      action: 'unauthorized_access_attempt',
      resource: 'reports',
      details: { 
        action: 'export',
        endpoint: req.path 
      },
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent') || 'unknown',
      department: req.user.department,
      role: req.user.role,
      sessionId: req.sessionID || 'unknown',
      severity: 'medium',
      status: 'failure'
    });
    
    return res.status(403).json({ 
      error: 'Insufficient privileges to export data.' 
    });
  }
  
  next();
};

module.exports = {
  requireRole,
  requirePermission,
  requireDepartmentAccess,
  requireApproval,
  filterDataByPermissions,
  requireExportPermission
};