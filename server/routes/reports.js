const express = require('express');
const router = express.Router();
const FinancialData = require('../models/FinancialData');
const AuditLog = require('../models/AuditLog');
const { authenticate } = require('../middleware/auth');
const { 
  requirePermission, 
  requireExportPermission, 
  filterDataByPermissions 
} = require('../middleware/authorize');
const { validateReportRequest } = require('../utils/validation');
const { generateReport, scheduleReport } = require('../utils/reportGenerator');

// @route   POST /api/reports/generate
// @desc    Generate financial report
// @access  Private
router.post('/generate', 
  authenticate, 
  requirePermission('reports', 'read'),
  async (req, res) => {
    try {
      const { error } = validateReportRequest(req.body);
      if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }

      const {
        type,
        period,
        filters = {},
        format = 'json',
        includeCharts = true,
        includeDetails = false
      } = req.body;

      // Apply department access control
      if (!['executive', 'finance'].includes(req.user.role)) {
        if (filters.departments) {
          filters.departments = filters.departments.filter(d => d === req.user.department);
        } else {
          filters.departments = [req.user.department];
        }
      }

      let reportData;
      switch (type) {
        case 'budget_vs_actual':
          reportData = await generateBudgetVsActualReport(period, filters);
          break;
        case 'cash_flow':
          reportData = await generateCashFlowReport(period, filters);
          break;
        case 'variance_analysis':
          reportData = await generateVarianceAnalysisReport(period, filters);
          break;
        case 'department_summary':
          reportData = await generateDepartmentSummaryReport(period, filters);
          break;
        case 'compliance':
          reportData = await generateComplianceReport(period, filters);
          break;
        default:
          return res.status(400).json({ error: 'Invalid report type' });
      }

      // Log report generation
      await AuditLog.createLog({
        userId: req.user._id,
        username: req.user.username,
        action: 'report_generated',
        resource: 'reports',
        details: { 
          type, 
          period, 
          filters, 
          format,
          recordCount: reportData.data ? reportData.data.length : 0
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: req.user.department,
        role: req.user.role,
        sessionId: req.token?.substring(0, 10) || 'unknown',
        complianceFlags: ['financial_reporting']
      });

      const response = {
        id: generateReportId(),
        type,
        period,
        filters,
        data: reportData,
        metadata: {
          generatedBy: {
            id: req.user._id,
            username: req.user.username,
            name: `${req.user.firstName} ${req.user.lastName}`
          },
          generatedAt: new Date(),
          format,
          includeCharts,
          includeDetails
        }
      };

      res.json(response);
    } catch (error) {
      console.error('Generate report error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   POST /api/reports/export
// @desc    Export report in specified format
// @access  Private
router.post('/export', 
  authenticate, 
  requirePermission('reports', 'read'),
  requireExportPermission,
  async (req, res) => {
    try {
      const { reportId, format = 'pdf' } = req.body;

      if (!reportId) {
        return res.status(400).json({ error: 'Report ID is required' });
      }

      // For demo purposes, we'll re-generate the report
      // In production, you'd typically store and retrieve the report data
      const reportRequest = req.body.reportRequest;
      if (!reportRequest) {
        return res.status(400).json({ error: 'Report request data is required for export' });
      }

      const exportData = await generateReport(reportRequest, format);

      // Log export
      await AuditLog.createLog({
        userId: req.user._id,
        username: req.user.username,
        action: 'report_exported',
        resource: 'reports',
        details: { 
          reportId, 
          format,
          size: exportData.size || 'unknown'
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: req.user.department,
        role: req.user.role,
        sessionId: req.token?.substring(0, 10) || 'unknown',
        severity: 'medium',
        complianceFlags: ['financial_reporting', 'data_retention']
      });

      // Set appropriate headers for file download
      const timestamp = new Date().toISOString().slice(0, 10);
      const filename = `financial_report_${reportRequest.type}_${timestamp}.${format}`;
      
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Type', getContentType(format));

      if (format === 'json') {
        res.json(exportData);
      } else {
        res.send(exportData);
      }
    } catch (error) {
      console.error('Export report error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   POST /api/reports/schedule
// @desc    Schedule recurring report
// @access  Private
router.post('/schedule', 
  authenticate, 
  requirePermission('reports', 'write'),
  async (req, res) => {
    try {
      const {
        name,
        reportRequest,
        schedule, // { frequency: 'monthly', dayOfMonth: 1, time: '09:00' }
        recipients = [],
        format = 'pdf',
        isActive = true
      } = req.body;

      if (!name || !reportRequest || !schedule) {
        return res.status(400).json({ 
          error: 'Name, report request, and schedule are required' 
        });
      }

      // Validate report request
      const { error } = validateReportRequest(reportRequest);
      if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }

      // Apply department access control to scheduled report
      if (!['executive', 'finance'].includes(req.user.role)) {
        if (reportRequest.filters && reportRequest.filters.departments) {
          reportRequest.filters.departments = 
            reportRequest.filters.departments.filter(d => d === req.user.department);
        } else {
          if (!reportRequest.filters) reportRequest.filters = {};
          reportRequest.filters.departments = [req.user.department];
        }
      }

      const scheduledReport = await scheduleReport({
        name,
        reportRequest,
        schedule,
        recipients: recipients.length > 0 ? recipients : [req.user.email],
        format,
        isActive,
        createdBy: req.user._id,
        department: req.user.department
      });

      // Log scheduled report creation
      await AuditLog.createLog({
        userId: req.user._id,
        username: req.user.username,
        action: 'report_scheduled',
        resource: 'reports',
        details: { 
          name,
          schedule,
          recipients: recipients.length,
          format
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: req.user.department,
        role: req.user.role,
        sessionId: req.token?.substring(0, 10) || 'unknown',
        complianceFlags: ['financial_reporting']
      });

      res.status(201).json({
        message: 'Report scheduled successfully',
        scheduledReport: {
          id: scheduledReport.id,
          name: scheduledReport.name,
          schedule: scheduledReport.schedule,
          nextRun: scheduledReport.nextRun,
          isActive: scheduledReport.isActive
        }
      });
    } catch (error) {
      console.error('Schedule report error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   GET /api/reports/scheduled
// @desc    Get user's scheduled reports
// @access  Private
router.get('/scheduled', 
  authenticate, 
  requirePermission('reports', 'read'),
  async (req, res) => {
    try {
      // This would typically query a ScheduledReports collection
      // For now, we'll return a mock response
      const mockScheduledReports = [
        {
          id: 'sched_001',
          name: 'Monthly Department Budget Report',
          reportType: 'department_summary',
          schedule: { frequency: 'monthly', dayOfMonth: 1, time: '09:00' },
          format: 'pdf',
          recipients: [req.user.email],
          isActive: true,
          lastRun: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 days ago
          nextRun: new Date(Date.now() + 24 * 60 * 60 * 1000), // tomorrow
          createdAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000), // 90 days ago
          createdBy: req.user._id
        }
      ];

      res.json({
        scheduledReports: mockScheduledReports,
        count: mockScheduledReports.length
      });
    } catch (error) {
      console.error('Get scheduled reports error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   GET /api/reports/history
// @desc    Get report generation history
// @access  Private
router.get('/history', 
  authenticate, 
  requirePermission('reports', 'read'),
  async (req, res) => {
    try {
      const { page = 1, limit = 20 } = req.query;
      const skip = (parseInt(page) - 1) * parseInt(limit);

      // Query audit logs for report generation history
      const reportHistory = await AuditLog.find({
        userId: req.user._id,
        action: { $in: ['report_generated', 'report_exported'] },
        resource: 'reports'
      })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .select('action details createdAt');

      const total = await AuditLog.countDocuments({
        userId: req.user._id,
        action: { $in: ['report_generated', 'report_exported'] },
        resource: 'reports'
      });

      res.json({
        history: reportHistory,
        pagination: {
          current: parseInt(page),
          total: Math.ceil(total / parseInt(limit)),
          count: reportHistory.length,
          totalRecords: total
        }
      });
    } catch (error) {
      console.error('Get report history error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Helper functions for different report types
async function generateBudgetVsActualReport(period, filters) {
  const matchConditions = {
    'period.year': { $gte: period.startYear, $lte: period.endYear },
    isActive: true,
    status: 'approved'
  };

  if (period.startMonth) {
    matchConditions['period.month'] = { $gte: period.startMonth };
  }
  if (period.endMonth) {
    matchConditions['period.month'] = { 
      ...(matchConditions['period.month'] || {}),
      $lte: period.endMonth 
    };
  }

  if (filters.departments) {
    matchConditions.department = { $in: filters.departments };
  }
  if (filters.categories) {
    matchConditions.category = { $in: filters.categories };
  }
  if (filters.minAmount) {
    matchConditions.budgetAmount = { $gte: filters.minAmount };
  }
  if (filters.maxAmount) {
    matchConditions.budgetAmount = { 
      ...(matchConditions.budgetAmount || {}),
      $lte: filters.maxAmount 
    };
  }

  const data = await FinancialData.aggregate([
    { $match: matchConditions },
    {
      $group: {
        _id: {
          year: '$period.year',
          month: '$period.month',
          department: '$department',
          category: '$category'
        },
        totalBudget: { $sum: '$budgetAmount' },
        totalActual: { $sum: '$actualAmount' },
        totalVariance: { $sum: '$variance' },
        recordCount: { $sum: 1 }
      }
    },
    {
      $addFields: {
        variancePercentage: {
          $cond: {
            if: { $eq: ['$totalBudget', 0] },
            then: 0,
            else: { $multiply: [{ $divide: ['$totalVariance', '$totalBudget'] }, 100] }
          }
        }
      }
    },
    { $sort: { '_id.year': 1, '_id.month': 1, '_id.department': 1 } }
  ]);

  // Calculate summary
  const summary = data.reduce((acc, curr) => ({
    totalBudget: acc.totalBudget + curr.totalBudget,
    totalActual: acc.totalActual + curr.totalActual,
    totalVariance: acc.totalVariance + curr.totalVariance,
    recordCount: acc.recordCount + curr.recordCount
  }), { totalBudget: 0, totalActual: 0, totalVariance: 0, recordCount: 0 });

  summary.variancePercentage = summary.totalBudget ? 
    (summary.totalVariance / summary.totalBudget) * 100 : 0;

  return { summary, data };
}

async function generateCashFlowReport(period, filters) {
  const years = [];
  for (let year = period.startYear; year <= period.endYear; year++) {
    years.push(year);
  }

  const months = [];
  if (period.startMonth && period.endMonth) {
    for (let month = period.startMonth; month <= period.endMonth; month++) {
      months.push(month);
    }
  } else {
    for (let month = 1; month <= 12; month++) {
      months.push(month);
    }
  }

  const cashFlowData = [];
  for (const year of years) {
    const yearData = await FinancialData.getCashFlowData(year, months);
    cashFlowData.push(...yearData.map(item => ({ ...item, year })));
  }

  // Filter by departments if specified
  if (filters.departments) {
    // This would require modifying the getCashFlowData method to accept department filter
    // For now, we'll use the data as is
  }

  return { data: cashFlowData };
}

async function generateVarianceAnalysisReport(period, filters) {
  const matchConditions = {
    'period.year': { $gte: period.startYear, $lte: period.endYear },
    isActive: true,
    status: 'approved',
    $expr: { $ne: ['$variancePercentage', 0] }
  };

  if (filters.departments) {
    matchConditions.department = { $in: filters.departments };
  }

  const data = await FinancialData.find(matchConditions)
    .populate('lastModifiedBy', 'firstName lastName username')
    .sort({ variancePercentage: -1 })
    .limit(100);

  const analysis = {
    totalRecords: data.length,
    positiveVariances: data.filter(item => item.variancePercentage > 0).length,
    negativeVariances: data.filter(item => item.variancePercentage < 0).length,
    avgVariancePercentage: data.reduce((sum, item) => sum + Math.abs(item.variancePercentage), 0) / data.length,
    significantVariances: data.filter(item => Math.abs(item.variancePercentage) > 20).length
  };

  return { analysis, data };
}

async function generateDepartmentSummaryReport(period, filters) {
  const departments = filters.departments || 
    ['finance', 'operations', 'procurement', 'it', 'hr', 'sales', 'marketing'];

  const summaries = [];
  for (const department of departments) {
    const summary = await FinancialData.getDepartmentSummary(
      department, 
      period.startYear,
      period.startMonth
    );
    summaries.push({ department, ...summary });
  }

  return { data: summaries };
}

async function generateComplianceReport(period, filters) {
  const startDate = new Date(period.startYear, (period.startMonth || 1) - 1, 1);
  const endDate = new Date(period.endYear, (period.endMonth || 12), 0);

  const complianceData = await AuditLog.getComplianceReport(
    startDate, 
    endDate, 
    ['financial_reporting', 'sox', 'access_control']
  );

  const securityAlerts = await AuditLog.getSecurityAlerts(30); // Last 30 days

  return {
    period: { startDate, endDate },
    complianceMetrics: complianceData,
    securityAlerts: securityAlerts.slice(0, 20), // Top 20 alerts
    summary: {
      totalAuditEntries: complianceData.length,
      criticalIssues: securityAlerts.filter(alert => alert.severity === 'critical').length,
      complianceScore: calculateComplianceScore(complianceData)
    }
  };
}

// Utility functions
function generateReportId() {
  return `rpt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function getContentType(format) {
  const contentTypes = {
    pdf: 'application/pdf',
    excel: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    csv: 'text/csv',
    json: 'application/json'
  };
  return contentTypes[format] || 'application/octet-stream';
}

function calculateComplianceScore(complianceData) {
  if (complianceData.length === 0) return 100;
  
  const totalEntries = complianceData.reduce((sum, item) => sum + item.count, 0);
  const failures = complianceData.reduce((sum, item) => sum + item.failureCount, 0);
  
  return Math.max(0, Math.round(((totalEntries - failures) / totalEntries) * 100));
}

module.exports = router;