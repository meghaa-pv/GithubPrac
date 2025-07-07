const express = require('express');
const router = express.Router();
const FinancialData = require('../models/FinancialData');
const AuditLog = require('../models/AuditLog');
const { authenticate } = require('../middleware/auth');
const { 
  requirePermission, 
  requireDepartmentAccess, 
  requireApproval,
  filterDataByPermissions 
} = require('../middleware/authorize');
const { 
  auditDataModification, 
  auditHighValueTransaction,
  auditBulkOperation 
} = require('../middleware/audit');
const { validateFinancialData } = require('../utils/validation');

// @route   GET /api/financial-data
// @desc    Get financial data with filters
// @access  Private
router.get('/', 
  authenticate, 
  requirePermission('budgets', 'read'),
  filterDataByPermissions,
  async (req, res) => {
    try {
      const {
        department,
        year,
        month,
        quarter,
        category,
        status,
        page = 1,
        limit = 50,
        sortBy = 'updatedAt',
        sortOrder = 'desc'
      } = req.query;

      // Build query
      const query = { isActive: true };

      // Department access control
      if (!['executive', 'finance'].includes(req.user.role)) {
        query.department = req.user.department;
      } else if (department) {
        query.department = department;
      }

      if (year) query['period.year'] = parseInt(year);
      if (month) query['period.month'] = parseInt(month);
      if (quarter) query['period.quarter'] = parseInt(quarter);
      if (category) query.category = category;
      if (status) query.status = status;

      // Pagination
      const skip = (parseInt(page) - 1) * parseInt(limit);
      const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

      const [data, total] = await Promise.all([
        FinancialData.find(query)
          .populate('lastModifiedBy', 'firstName lastName username')
          .populate('approvedBy', 'firstName lastName username')
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit)),
        FinancialData.countDocuments(query)
      ]);

      res.json({
        data,
        pagination: {
          current: parseInt(page),
          total: Math.ceil(total / parseInt(limit)),
          count: data.length,
          totalRecords: total
        }
      });
    } catch (error) {
      console.error('Get financial data error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   GET /api/financial-data/:id
// @desc    Get single financial data record
// @access  Private
router.get('/:id', 
  authenticate, 
  requirePermission('budgets', 'read'),
  requireDepartmentAccess,
  async (req, res) => {
    try {
      const data = await FinancialData.findById(req.params.id)
        .populate('lastModifiedBy', 'firstName lastName username')
        .populate('approvedBy', 'firstName lastName username');

      if (!data || !data.isActive) {
        return res.status(404).json({ error: 'Financial data not found' });
      }

      // Check department access
      if (!['executive', 'finance'].includes(req.user.role) && 
          data.department !== req.user.department) {
        return res.status(403).json({ 
          error: 'Access denied to this department data' 
        });
      }

      res.json(data);
    } catch (error) {
      console.error('Get financial data by ID error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   POST /api/financial-data
// @desc    Create new financial data
// @access  Private
router.post('/', 
  authenticate, 
  requirePermission('budgets', 'write'),
  requireApproval,
  auditDataModification,
  auditHighValueTransaction(),
  async (req, res) => {
    try {
      const { error } = validateFinancialData(req.body);
      if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }

      // Set department if not provided (for non-executives/finance)
      if (!['executive', 'finance'].includes(req.user.role)) {
        req.body.department = req.user.department;
      }

      // Calculate quarter from month
      const quarter = Math.ceil(req.body.period.month / 3);
      req.body.period.quarter = quarter;

      const financialData = new FinancialData({
        ...req.body,
        lastModifiedBy: req.user._id
      });

      await financialData.save();

      const populatedData = await FinancialData.findById(financialData._id)
        .populate('lastModifiedBy', 'firstName lastName username');

      res.status(201).json(populatedData);
    } catch (error) {
      console.error('Create financial data error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   PUT /api/financial-data/:id
// @desc    Update financial data
// @access  Private
router.put('/:id', 
  authenticate, 
  requirePermission('budgets', 'write'),
  requireDepartmentAccess,
  requireApproval,
  auditDataModification,
  auditHighValueTransaction(),
  async (req, res) => {
    try {
      const { error } = validateFinancialData(req.body);
      if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }

      const existingData = await FinancialData.findById(req.params.id);
      if (!existingData || !existingData.isActive) {
        return res.status(404).json({ error: 'Financial data not found' });
      }

      // Check department access
      if (!['executive', 'finance'].includes(req.user.role) && 
          existingData.department !== req.user.department) {
        return res.status(403).json({ 
          error: 'Access denied to modify this department data' 
        });
      }

      // Store original data for audit
      req.auditBefore = existingData.toObject();

      // Calculate quarter from month if month is updated
      if (req.body.period && req.body.period.month) {
        req.body.period.quarter = Math.ceil(req.body.period.month / 3);
      }

      // Update version for tracking
      req.body.version = existingData.version + 1;
      req.body.lastModifiedBy = req.user._id;

      const updatedData = await FinancialData.findByIdAndUpdate(
        req.params.id,
        req.body,
        { new: true, runValidators: true }
      ).populate('lastModifiedBy', 'firstName lastName username')
       .populate('approvedBy', 'firstName lastName username');

      res.json(updatedData);
    } catch (error) {
      console.error('Update financial data error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   DELETE /api/financial-data/:id
// @desc    Soft delete financial data
// @access  Private
router.delete('/:id', 
  authenticate, 
  requirePermission('budgets', 'delete'),
  requireDepartmentAccess,
  auditDataModification,
  async (req, res) => {
    try {
      const existingData = await FinancialData.findById(req.params.id);
      if (!existingData || !existingData.isActive) {
        return res.status(404).json({ error: 'Financial data not found' });
      }

      // Check department access
      if (!['executive', 'finance'].includes(req.user.role) && 
          existingData.department !== req.user.department) {
        return res.status(403).json({ 
          error: 'Access denied to delete this department data' 
        });
      }

      // Soft delete
      existingData.isActive = false;
      existingData.lastModifiedBy = req.user._id;
      await existingData.save();

      res.json({ message: 'Financial data deleted successfully' });
    } catch (error) {
      console.error('Delete financial data error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   POST /api/financial-data/bulk
// @desc    Bulk create/update financial data
// @access  Private
router.post('/bulk', 
  authenticate, 
  requirePermission('budgets', 'write'),
  auditBulkOperation,
  async (req, res) => {
    try {
      if (!Array.isArray(req.body) || req.body.length === 0) {
        return res.status(400).json({ 
          error: 'Request body must be a non-empty array' 
        });
      }

      const results = {
        created: 0,
        updated: 0,
        errors: []
      };

      for (let i = 0; i < req.body.length; i++) {
        try {
          const item = req.body[i];
          
          // Validate each item
          const { error } = validateFinancialData(item);
          if (error) {
            results.errors.push({
              index: i,
              error: error.details[0].message
            });
            continue;
          }

          // Set department for non-executives/finance
          if (!['executive', 'finance'].includes(req.user.role)) {
            item.department = req.user.department;
          }

          // Calculate quarter
          item.period.quarter = Math.ceil(item.period.month / 3);
          item.lastModifiedBy = req.user._id;

          if (item._id) {
            // Update existing
            await FinancialData.findByIdAndUpdate(
              item._id,
              { ...item, version: (item.version || 1) + 1 },
              { upsert: false, runValidators: true }
            );
            results.updated++;
          } else {
            // Create new
            const newData = new FinancialData(item);
            await newData.save();
            results.created++;
          }
        } catch (itemError) {
          results.errors.push({
            index: i,
            error: itemError.message
          });
        }
      }

      res.json({
        message: 'Bulk operation completed',
        results
      });
    } catch (error) {
      console.error('Bulk operation error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// @route   POST /api/financial-data/:id/approve
// @desc    Approve financial data
// @access  Private
router.post('/:id/approve', 
  authenticate, 
  requirePermission('budgets', 'approve'),
  async (req, res) => {
    try {
      const data = await FinancialData.findById(req.params.id);
      if (!data || !data.isActive) {
        return res.status(404).json({ error: 'Financial data not found' });
      }

      if (data.status === 'approved') {
        return res.status(400).json({ error: 'Data is already approved' });
      }

      data.status = 'approved';
      data.approvedBy = req.user._id;
      data.approvalDate = new Date();
      await data.save();

      // Log approval
      await AuditLog.createLog({
        userId: req.user._id,
        username: req.user.username,
        action: 'data_approved',
        resource: 'financial_data',
        resourceId: data._id.toString(),
        details: {
          amount: data.budgetAmount,
          department: data.department,
          category: data.category
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        department: req.user.department,
        role: req.user.role,
        sessionId: req.token?.substring(0, 10) || 'unknown',
        complianceFlags: ['financial_reporting', 'sox']
      });

      const populatedData = await FinancialData.findById(data._id)
        .populate('lastModifiedBy', 'firstName lastName username')
        .populate('approvedBy', 'firstName lastName username');

      res.json(populatedData);
    } catch (error) {
      console.error('Approve financial data error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

module.exports = router;