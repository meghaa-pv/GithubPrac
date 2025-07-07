const express = require('express');
const router = express.Router();
const AuditLog = require('../models/AuditLog');
const { authenticate } = require('../middleware/auth');
const { requirePermission, requireRole } = require('../middleware/authorize');

// @route   GET /api/audit/logs
// @desc    Get audit logs with filters
// @access  Private (Finance, Executive)
router.get('/logs', 
  authenticate, 
  requirePermission('audit', 'read'),
  async (req, res) => {
    try {
      const {
        action,
        resource,
        severity,
        department,
        startDate,
        endDate,
        page = 1,
        limit = 50,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      // Build query
      const query = {};
      
      if (action) query.action = action;
      if (resource) query.resource = resource;
      if (severity) query.severity = severity;
      
      // Department access control
      if (!['executive', 'finance'].includes(req.user.role)) {
        query.department = req.user.department;
      } else if (department) {
        query.department = department;
      }

      if (startDate || endDate) {
        query.createdAt = {};
        if (startDate) query.createdAt.$gte = new Date(startDate);
        if (endDate) query.createdAt.$lte = new Date(endDate);
      }

      // Pagination
      const skip = (parseInt(page) - 1) * parseInt(limit);
      const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

      const [logs, total] = await Promise.all([
        AuditLog.find(query)
          .populate('userId', 'firstName lastName username')
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit)),
        AuditLog.countDocuments(query)
      ]);

      res.json({
        logs,
        pagination: {
          current: parseInt(page),
          total: Math.ceil(total / parseInt(limit)),
          count: logs.length,
          totalRecords: total
        }
      });
    } catch (error) {
      console.error('Get audit logs error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   GET /api/audit/security-alerts
// @desc    Get security alerts
// @access  Private (Finance, Executive)
router.get('/security-alerts', 
  authenticate, 
  requireRole(['executive', 'finance']),
  async (req, res) => {
    try {
      const { days = 7, limit = 20 } = req.query;
      
      const alerts = await AuditLog.getSecurityAlerts(parseInt(days));
      
      res.json({
        alerts: alerts.slice(0, parseInt(limit)),
        summary: {
          total: alerts.length,
          critical: alerts.filter(a => a.severity === 'critical').length,
          high: alerts.filter(a => a.severity === 'high').length
        }
      });
    } catch (error) {
      console.error('Get security alerts error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   GET /api/audit/compliance
// @desc    Get compliance report
// @access  Private (Finance, Executive)
router.get('/compliance', 
  authenticate, 
  requireRole(['executive', 'finance']),
  async (req, res) => {
    try {
      const { startDate, endDate, flags } = req.query;
      
      const start = startDate ? new Date(startDate) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const end = endDate ? new Date(endDate) : new Date();
      const complianceFlags = flags ? flags.split(',') : [];
      
      const report = await AuditLog.getComplianceReport(start, end, complianceFlags);
      
      res.json({
        period: { startDate: start, endDate: end },
        report,
        summary: {
          totalEntries: report.length,
          complianceScore: calculateComplianceScore(report)
        }
      });
    } catch (error) {
      console.error('Get compliance report error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

function calculateComplianceScore(data) {
  if (data.length === 0) return 100;
  
  const totalEntries = data.reduce((sum, item) => sum + item.count, 0);
  const failures = data.reduce((sum, item) => sum + item.failureCount, 0);
  
  return Math.max(0, Math.round(((totalEntries - failures) / totalEntries) * 100));
}

module.exports = router;