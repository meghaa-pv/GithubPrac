const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  username: {
    type: String,
    required: true
  },
  action: {
    type: String,
    required: true,
    enum: [
      'login',
      'logout',
      'login_failed',
      'password_changed',
      'mfa_enabled',
      'mfa_disabled',
      'data_created',
      'data_updated',
      'data_deleted',
      'report_generated',
      'report_exported',
      'permission_changed',
      'unauthorized_access_attempt',
      'bulk_import',
      'bulk_export'
    ]
  },
  resource: {
    type: String,
    enum: ['auth', 'financial_data', 'reports', 'users', 'system'],
    required: true
  },
  resourceId: {
    type: String,
    default: null
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: {
    type: String,
    required: true
  },
  department: {
    type: String,
    required: true
  },
  role: {
    type: String,
    required: true
  },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },
  status: {
    type: String,
    enum: ['success', 'failure', 'warning'],
    default: 'success'
  },
  sessionId: {
    type: String,
    required: true
  },
  beforeValue: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  afterValue: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  complianceFlags: [{
    type: String,
    enum: ['sox', 'gdpr', 'data_retention', 'access_control', 'financial_reporting']
  }],
  requiresReview: {
    type: Boolean,
    default: false
  },
  reviewedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  reviewedAt: {
    type: Date,
    default: null
  },
  reviewNotes: {
    type: String,
    default: null
  }
}, {
  timestamps: true
});

// Indexes for efficient querying
auditLogSchema.index({ userId: 1, createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });
auditLogSchema.index({ resource: 1, resourceId: 1 });
auditLogSchema.index({ severity: 1, requiresReview: 1 });
auditLogSchema.index({ department: 1, role: 1 });
auditLogSchema.index({ createdAt: -1 });
auditLogSchema.index({ complianceFlags: 1 });

// TTL index for automatic cleanup (keep logs for 7 years for compliance)
auditLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 7 * 365 * 24 * 60 * 60 });

// Static methods for audit reporting
auditLogSchema.statics.getSecurityAlerts = function(days = 7) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  return this.aggregate([
    {
      $match: {
        createdAt: { $gte: startDate },
        $or: [
          { action: 'unauthorized_access_attempt' },
          { action: 'login_failed' },
          { severity: 'high' },
          { severity: 'critical' }
        ]
      }
    },
    {
      $group: {
        _id: {
          userId: '$userId',
          action: '$action',
          date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }
        },
        count: { $sum: 1 },
        lastOccurrence: { $max: '$createdAt' },
        ipAddresses: { $addToSet: '$ipAddress' }
      }
    },
    {
      $lookup: {
        from: 'users',
        localField: '_id.userId',
        foreignField: '_id',
        as: 'user'
      }
    },
    { $sort: { lastOccurrence: -1 } }
  ]);
};

auditLogSchema.statics.getUserActivity = function(userId, days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  return this.aggregate([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        createdAt: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: {
          action: '$action',
          resource: '$resource',
          date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }
        },
        count: { $sum: 1 },
        lastActivity: { $max: '$createdAt' }
      }
    },
    { $sort: { lastActivity: -1 } }
  ]);
};

auditLogSchema.statics.getComplianceReport = function(startDate, endDate, flags = []) {
  const matchConditions = {
    createdAt: { $gte: startDate, $lte: endDate }
  };
  
  if (flags.length > 0) {
    matchConditions.complianceFlags = { $in: flags };
  }
  
  return this.aggregate([
    { $match: matchConditions },
    {
      $group: {
        _id: {
          department: '$department',
          action: '$action',
          complianceFlag: { $arrayElemAt: ['$complianceFlags', 0] }
        },
        count: { $sum: 1 },
        failureCount: {
          $sum: { $cond: [{ $eq: ['$status', 'failure'] }, 1, 0] }
        },
        warningCount: {
          $sum: { $cond: [{ $eq: ['$status', 'warning'] }, 1, 0] }
        }
      }
    },
    {
      $addFields: {
        successRate: {
          $multiply: [
            { $divide: [{ $subtract: ['$count', '$failureCount'] }, '$count'] },
            100
          ]
        }
      }
    },
    { $sort: { '_id.department': 1, '_id.action': 1 } }
  ]);
};

auditLogSchema.statics.getDataModificationHistory = function(resourceId, limit = 50) {
  return this.find({
    resourceId: resourceId,
    action: { $in: ['data_created', 'data_updated', 'data_deleted'] }
  })
  .populate('userId', 'firstName lastName username')
  .sort({ createdAt: -1 })
  .limit(limit);
};

// Method to create audit log entry
auditLogSchema.statics.createLog = function(logData) {
  // Auto-assign severity based on action
  if (!logData.severity) {
    const highSeverityActions = ['unauthorized_access_attempt', 'data_deleted', 'permission_changed'];
    const mediumSeverityActions = ['login_failed', 'data_updated', 'bulk_export'];
    
    if (highSeverityActions.includes(logData.action)) {
      logData.severity = 'high';
    } else if (mediumSeverityActions.includes(logData.action)) {
      logData.severity = 'medium';
    }
  }
  
  // Auto-assign compliance flags
  if (!logData.complianceFlags) {
    logData.complianceFlags = [];
    
    if (['data_created', 'data_updated', 'data_deleted'].includes(logData.action)) {
      logData.complianceFlags.push('financial_reporting', 'sox');
    }
    
    if (['login', 'login_failed', 'unauthorized_access_attempt'].includes(logData.action)) {
      logData.complianceFlags.push('access_control');
    }
  }
  
  // Mark for review if high severity or critical
  if (['high', 'critical'].includes(logData.severity)) {
    logData.requiresReview = true;
  }
  
  return this.create(logData);
};

module.exports = mongoose.model('AuditLog', auditLogSchema);