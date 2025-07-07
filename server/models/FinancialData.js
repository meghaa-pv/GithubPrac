const mongoose = require('mongoose');

const financialDataSchema = new mongoose.Schema({
  period: {
    year: {
      type: Number,
      required: true
    },
    month: {
      type: Number,
      required: true,
      min: 1,
      max: 12
    },
    quarter: {
      type: Number,
      required: true,
      min: 1,
      max: 4
    }
  },
  department: {
    type: String,
    enum: ['finance', 'operations', 'procurement', 'it', 'hr', 'sales', 'marketing'],
    required: true
  },
  category: {
    type: String,
    enum: ['revenue', 'expenses', 'capital', 'operational'],
    required: true
  },
  subcategory: {
    type: String,
    required: true
  },
  budgetAmount: {
    type: Number,
    required: true,
    default: 0
  },
  actualAmount: {
    type: Number,
    required: true,
    default: 0
  },
  variance: {
    type: Number,
    default: function() {
      return this.actualAmount - this.budgetAmount;
    }
  },
  variancePercentage: {
    type: Number,
    default: function() {
      if (this.budgetAmount === 0) return 0;
      return ((this.actualAmount - this.budgetAmount) / this.budgetAmount) * 100;
    }
  },
  currency: {
    type: String,
    default: 'USD',
    enum: ['USD', 'EUR', 'GBP', 'CAD', 'AUD']
  },
  description: {
    type: String,
    trim: true
  },
  tags: [String],
  approvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  approvalDate: Date,
  status: {
    type: String,
    enum: ['draft', 'pending', 'approved', 'rejected'],
    default: 'draft'
  },
  lastModifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  version: {
    type: Number,
    default: 1
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Compound indexes for efficient querying
financialDataSchema.index({ 'period.year': 1, 'period.month': 1, department: 1 });
financialDataSchema.index({ department: 1, category: 1 });
financialDataSchema.index({ status: 1, approvalDate: 1 });
financialDataSchema.index({ lastModifiedBy: 1, updatedAt: -1 });

// Virtual for period string
financialDataSchema.virtual('periodString').get(function() {
  return `${this.period.year}-${String(this.period.month).padStart(2, '0')}`;
});

// Pre-save middleware to calculate variance
financialDataSchema.pre('save', function(next) {
  this.variance = this.actualAmount - this.budgetAmount;
  if (this.budgetAmount !== 0) {
    this.variancePercentage = ((this.actualAmount - this.budgetAmount) / this.budgetAmount) * 100;
  } else {
    this.variancePercentage = 0;
  }
  next();
});

// Static methods for aggregations
financialDataSchema.statics.getDepartmentSummary = function(department, year, month) {
  return this.aggregate([
    {
      $match: {
        department: department,
        'period.year': year,
        ...(month && { 'period.month': month }),
        isActive: true
      }
    },
    {
      $group: {
        _id: '$category',
        totalBudget: { $sum: '$budgetAmount' },
        totalActual: { $sum: '$actualAmount' },
        totalVariance: { $sum: '$variance' },
        count: { $sum: 1 }
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
    }
  ]);
};

financialDataSchema.statics.getCashFlowData = function(year, months) {
  return this.aggregate([
    {
      $match: {
        'period.year': year,
        'period.month': { $in: months },
        isActive: true
      }
    },
    {
      $group: {
        _id: {
          month: '$period.month',
          category: '$category'
        },
        totalActual: { $sum: '$actualAmount' }
      }
    },
    {
      $group: {
        _id: '$_id.month',
        revenue: {
          $sum: {
            $cond: [{ $eq: ['$_id.category', 'revenue'] }, '$totalActual', 0]
          }
        },
        expenses: {
          $sum: {
            $cond: [{ $ne: ['$_id.category', 'revenue'] }, '$totalActual', 0]
          }
        }
      }
    },
    {
      $addFields: {
        netCashFlow: { $subtract: ['$revenue', '$expenses'] }
      }
    },
    { $sort: { _id: 1 } }
  ]);
};

financialDataSchema.statics.getVarianceAlerts = function(thresholdPercentage = 10) {
  return this.aggregate([
    {
      $match: {
        isActive: true,
        status: 'approved',
        $expr: {
          $gt: [
            { $abs: '$variancePercentage' },
            thresholdPercentage
          ]
        }
      }
    },
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
    { $sort: { variancePercentage: -1 } }
  ]);
};

module.exports = mongoose.model('FinancialData', financialDataSchema);