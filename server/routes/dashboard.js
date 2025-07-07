const express = require('express');
const router = express.Router();
const FinancialData = require('../models/FinancialData');
const AuditLog = require('../models/AuditLog');
const { authenticate } = require('../middleware/auth');
const { requirePermission, filterDataByPermissions } = require('../middleware/authorize');

// @route   GET /api/dashboard/executive
// @desc    Get executive dashboard data
// @access  Private (Executive, Finance)
router.get('/executive', 
  authenticate, 
  requirePermission('budgets', 'read'),
  async (req, res) => {
    try {
      // Only executives and finance can access executive dashboard
      if (!['executive', 'finance'].includes(req.user.role)) {
        return res.status(403).json({ 
          error: 'Access denied. Executive privileges required.' 
        });
      }

      const currentYear = new Date().getFullYear();
      const currentMonth = new Date().getMonth() + 1;
      
      // Get current year data
      const [
        budgetVsActual,
        cashFlowData,
        varianceAlerts,
        departmentSummaries,
        recentActivities
      ] = await Promise.all([
        getBudgetVsActualSummary(currentYear),
        getCashFlowAnalysis(currentYear),
        getVarianceAlerts(),
        getDepartmentSummaries(currentYear, currentMonth),
        getRecentActivities(7) // Last 7 days
      ]);

      // Calculate key metrics
      const keyMetrics = calculateKeyMetrics(budgetVsActual, cashFlowData);

      res.json({
        keyMetrics,
        budgetVsActual,
        cashFlow: cashFlowData,
        varianceAlerts,
        departmentSummaries,
        recentActivities,
        lastUpdated: new Date()
      });
    } catch (error) {
      console.error('Executive dashboard error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   GET /api/dashboard/department/:department
// @desc    Get department-specific dashboard
// @access  Private
router.get('/department/:department', 
  authenticate, 
  requirePermission('budgets', 'read'),
  filterDataByPermissions,
  async (req, res) => {
    try {
      const { department } = req.params;
      const currentYear = new Date().getFullYear();
      const currentMonth = new Date().getMonth() + 1;

      // Check department access
      if (!['executive', 'finance'].includes(req.user.role) && 
          req.user.department !== department) {
        return res.status(403).json({ 
          error: 'Access denied to this department data' 
        });
      }

      const [
        departmentBudget,
        monthlyTrends,
        categoryBreakdown,
        upcomingItems,
        departmentAlerts
      ] = await Promise.all([
        getDepartmentBudgetSummary(department, currentYear),
        getDepartmentMonthlyTrends(department, currentYear),
        getDepartmentCategoryBreakdown(department, currentYear, currentMonth),
        getUpcomingBudgetItems(department),
        getDepartmentVarianceAlerts(department)
      ]);

      res.json({
        department,
        budgetSummary: departmentBudget,
        monthlyTrends,
        categoryBreakdown,
        upcomingItems,
        alerts: departmentAlerts,
        lastUpdated: new Date()
      });
    } catch (error) {
      console.error('Department dashboard error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   GET /api/dashboard/alerts
// @desc    Get all alerts and notifications
// @access  Private
router.get('/alerts', 
  authenticate, 
  requirePermission('budgets', 'read'),
  async (req, res) => {
    try {
      const { severity, limit = 20 } = req.query;

      // Build query for user's accessible departments
      let departments = [];
      if (['executive', 'finance'].includes(req.user.role)) {
        departments = ['finance', 'operations', 'procurement', 'it', 'hr', 'sales', 'marketing'];
      } else {
        departments = [req.user.department];
      }

      const [
        varianceAlerts,
        budgetOverruns,
        approvalPending,
        securityAlerts
      ] = await Promise.all([
        getVarianceAlerts(departments, severity),
        getBudgetOverruns(departments),
        getApprovalPendingItems(departments),
        getSecurityAlerts(req.user._id, 7) // Last 7 days
      ]);

      const allAlerts = [
        ...varianceAlerts.map(alert => ({
          ...alert,
          type: 'variance',
          priority: Math.abs(alert.variancePercentage) > 25 ? 'high' : 'medium'
        })),
        ...budgetOverruns.map(alert => ({
          ...alert,
          type: 'budget_overrun',
          priority: 'high'
        })),
        ...approvalPending.map(alert => ({
          ...alert,
          type: 'approval_pending',
          priority: 'medium'
        })),
        ...securityAlerts.map(alert => ({
          ...alert,
          type: 'security',
          priority: alert.severity === 'high' ? 'high' : 'medium'
        }))
      ].sort((a, b) => {
        const priorityOrder = { high: 3, medium: 2, low: 1 };
        return priorityOrder[b.priority] - priorityOrder[a.priority];
      }).slice(0, parseInt(limit));

      res.json({
        alerts: allAlerts,
        summary: {
          total: allAlerts.length,
          high: allAlerts.filter(a => a.priority === 'high').length,
          medium: allAlerts.filter(a => a.priority === 'medium').length,
          low: allAlerts.filter(a => a.priority === 'low').length
        }
      });
    } catch (error) {
      console.error('Alerts dashboard error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   GET /api/dashboard/metrics
// @desc    Get key financial metrics
// @access  Private
router.get('/metrics', 
  authenticate, 
  requirePermission('budgets', 'read'),
  async (req, res) => {
    try {
      const { period = 'current_year' } = req.query;
      
      let year, month;
      if (period === 'current_year') {
        year = new Date().getFullYear();
      } else if (period === 'current_month') {
        year = new Date().getFullYear();
        month = new Date().getMonth() + 1;
      }

      // Build department filter
      let departmentFilter = {};
      if (!['executive', 'finance'].includes(req.user.role)) {
        departmentFilter.department = req.user.department;
      }

      const metrics = await FinancialData.aggregate([
        {
          $match: {
            'period.year': year,
            ...(month && { 'period.month': month }),
            ...departmentFilter,
            isActive: true,
            status: 'approved'
          }
        },
        {
          $group: {
            _id: null,
            totalBudget: { $sum: '$budgetAmount' },
            totalActual: { $sum: '$actualAmount' },
            totalVariance: { $sum: '$variance' },
            avgVariancePercentage: { $avg: '$variancePercentage' },
            recordCount: { $sum: 1 },
            categories: {
              $push: {
                category: '$category',
                budget: '$budgetAmount',
                actual: '$actualAmount'
              }
            }
          }
        },
        {
          $addFields: {
            budgetUtilization: {
              $cond: {
                if: { $eq: ['$totalBudget', 0] },
                then: 0,
                else: { $multiply: [{ $divide: ['$totalActual', '$totalBudget'] }, 100] }
              }
            },
            overBudget: { $gt: ['$totalActual', '$totalBudget'] },
            variancePercentage: {
              $cond: {
                if: { $eq: ['$totalBudget', 0] },
                then: 0,
                else: { $multiply: [{ $divide: ['$totalVariance', '$totalBudget'] }, 100] }
              }
            }
          }
        }
      ]);

      const result = metrics[0] || {
        totalBudget: 0,
        totalActual: 0,
        totalVariance: 0,
        budgetUtilization: 0,
        avgVariancePercentage: 0,
        recordCount: 0,
        overBudget: false,
        variancePercentage: 0
      };

      res.json({
        period,
        metrics: result,
        lastUpdated: new Date()
      });
    } catch (error) {
      console.error('Metrics dashboard error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Helper functions
async function getBudgetVsActualSummary(year) {
  return FinancialData.aggregate([
    {
      $match: {
        'period.year': year,
        isActive: true,
        status: 'approved'
      }
    },
    {
      $group: {
        _id: '$period.month',
        totalBudget: { $sum: '$budgetAmount' },
        totalActual: { $sum: '$actualAmount' },
        varianceAmount: { $sum: '$variance' }
      }
    },
    {
      $addFields: {
        month: '$_id',
        variancePercentage: {
          $cond: {
            if: { $eq: ['$totalBudget', 0] },
            then: 0,
            else: { $multiply: [{ $divide: ['$varianceAmount', '$totalBudget'] }, 100] }
          }
        }
      }
    },
    { $sort: { month: 1 } }
  ]);
}

async function getCashFlowAnalysis(year) {
  return FinancialData.getCashFlowData(year, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
}

async function getVarianceAlerts(departments = null, severity = null) {
  let matchConditions = {
    isActive: true,
    status: 'approved',
    $expr: { $gt: [{ $abs: '$variancePercentage' }, 10] }
  };

  if (departments && departments.length > 0) {
    matchConditions.department = { $in: departments };
  }

  return FinancialData.aggregate([
    { $match: matchConditions },
    {
      $lookup: {
        from: 'users',
        localField: 'lastModifiedBy',
        foreignField: '_id',
        as: 'modifiedBy'
      }
    },
    {
      $project: {
        department: 1,
        category: 1,
        subcategory: 1,
        budgetAmount: 1,
        actualAmount: 1,
        variance: 1,
        variancePercentage: 1,
        period: 1,
        'modifiedBy.firstName': 1,
        'modifiedBy.lastName': 1,
        updatedAt: 1
      }
    },
    { $sort: { variancePercentage: -1 } },
    { $limit: 10 }
  ]);
}

async function getDepartmentSummaries(year, month) {
  return FinancialData.aggregate([
    {
      $match: {
        'period.year': year,
        'period.month': month,
        isActive: true,
        status: 'approved'
      }
    },
    {
      $group: {
        _id: '$department',
        totalBudget: { $sum: '$budgetAmount' },
        totalActual: { $sum: '$actualAmount' },
        totalVariance: { $sum: '$variance' },
        recordCount: { $sum: 1 }
      }
    },
    {
      $addFields: {
        department: '$_id',
        variancePercentage: {
          $cond: {
            if: { $eq: ['$totalBudget', 0] },
            then: 0,
            else: { $multiply: [{ $divide: ['$totalVariance', '$totalBudget'] }, 100] }
          }
        },
        budgetUtilization: {
          $cond: {
            if: { $eq: ['$totalBudget', 0] },
            then: 0,
            else: { $multiply: [{ $divide: ['$totalActual', '$totalBudget'] }, 100] }
          }
        }
      }
    },
    { $sort: { totalBudget: -1 } }
  ]);
}

async function getRecentActivities(days) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  return AuditLog.find({
    createdAt: { $gte: startDate },
    action: { $in: ['data_created', 'data_updated', 'data_approved', 'data_deleted'] }
  })
  .populate('userId', 'firstName lastName username')
  .sort({ createdAt: -1 })
  .limit(20)
  .select('action resource details createdAt userId');
}

function calculateKeyMetrics(budgetVsActual, cashFlow) {
  const totalBudget = budgetVsActual.reduce((sum, item) => sum + item.totalBudget, 0);
  const totalActual = budgetVsActual.reduce((sum, item) => sum + item.totalActual, 0);
  const totalVariance = totalActual - totalBudget;
  const avgCashFlow = cashFlow.reduce((sum, item) => sum + item.netCashFlow, 0) / cashFlow.length;

  return {
    totalBudget,
    totalActual,
    totalVariance,
    variancePercentage: totalBudget ? ((totalVariance / totalBudget) * 100) : 0,
    budgetUtilization: totalBudget ? ((totalActual / totalBudget) * 100) : 0,
    avgMonthlyCashFlow: avgCashFlow || 0,
    isOverBudget: totalActual > totalBudget
  };
}

async function getDepartmentBudgetSummary(department, year) {
  return FinancialData.getDepartmentSummary(department, year);
}

async function getDepartmentMonthlyTrends(department, year) {
  return FinancialData.aggregate([
    {
      $match: {
        department: department,
        'period.year': year,
        isActive: true
      }
    },
    {
      $group: {
        _id: '$period.month',
        budget: { $sum: '$budgetAmount' },
        actual: { $sum: '$actualAmount' },
        variance: { $sum: '$variance' }
      }
    },
    {
      $addFields: {
        month: '$_id',
        variancePercentage: {
          $cond: {
            if: { $eq: ['$budget', 0] },
            then: 0,
            else: { $multiply: [{ $divide: ['$variance', '$budget'] }, 100] }
          }
        }
      }
    },
    { $sort: { month: 1 } }
  ]);
}

async function getDepartmentCategoryBreakdown(department, year, month) {
  return FinancialData.aggregate([
    {
      $match: {
        department: department,
        'period.year': year,
        'period.month': month,
        isActive: true,
        status: 'approved'
      }
    },
    {
      $group: {
        _id: '$category',
        budget: { $sum: '$budgetAmount' },
        actual: { $sum: '$actualAmount' },
        count: { $sum: 1 }
      }
    },
    {
      $addFields: {
        category: '$_id',
        variance: { $subtract: ['$actual', '$budget'] },
        variancePercentage: {
          $cond: {
            if: { $eq: ['$budget', 0] },
            then: 0,
            else: { $multiply: [{ $divide: [{ $subtract: ['$actual', '$budget'] }, '$budget'] }, 100] }
          }
        }
      }
    }
  ]);
}

async function getUpcomingBudgetItems(department) {
  const nextMonth = new Date();
  nextMonth.setMonth(nextMonth.getMonth() + 1);

  return FinancialData.find({
    department: department,
    'period.year': nextMonth.getFullYear(),
    'period.month': nextMonth.getMonth() + 1,
    isActive: true,
    status: { $in: ['draft', 'pending'] }
  })
  .populate('lastModifiedBy', 'firstName lastName')
  .sort({ budgetAmount: -1 })
  .limit(10);
}

async function getDepartmentVarianceAlerts(department) {
  return FinancialData.find({
    department: department,
    isActive: true,
    status: 'approved',
    $expr: { $gt: [{ $abs: '$variancePercentage' }, 15] }
  })
  .sort({ variancePercentage: -1 })
  .limit(5);
}

async function getBudgetOverruns(departments) {
  return FinancialData.find({
    department: { $in: departments },
    isActive: true,
    status: 'approved',
    $expr: { $gt: ['$actualAmount', '$budgetAmount'] }
  })
  .populate('lastModifiedBy', 'firstName lastName')
  .sort({ variance: -1 })
  .limit(10);
}

async function getApprovalPendingItems(departments) {
  return FinancialData.find({
    department: { $in: departments },
    isActive: true,
    status: 'pending'
  })
  .populate('lastModifiedBy', 'firstName lastName')
  .sort({ budgetAmount: -1 })
  .limit(10);
}

async function getSecurityAlerts(userId, days) {
  return AuditLog.getSecurityAlerts(days);
}

module.exports = router;