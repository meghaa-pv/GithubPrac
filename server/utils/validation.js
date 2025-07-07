const Joi = require('joi');

// User registration validation
const validateRegistration = (data) => {
  const schema = Joi.object({
    username: Joi.string()
      .alphanum()
      .min(3)
      .max(50)
      .required()
      .messages({
        'string.alphanum': 'Username must contain only alphanumeric characters',
        'string.min': 'Username must be at least 3 characters long',
        'string.max': 'Username cannot exceed 50 characters'
      }),
    email: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address'
      }),
    password: Joi.string()
      .min(8)
      .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])'))
      .required()
      .messages({
        'string.min': 'Password must be at least 8 characters long',
        'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'
      }),
    firstName: Joi.string()
      .min(1)
      .max(50)
      .required()
      .messages({
        'string.min': 'First name is required',
        'string.max': 'First name cannot exceed 50 characters'
      }),
    lastName: Joi.string()
      .min(1)
      .max(50)
      .required()
      .messages({
        'string.min': 'Last name is required',
        'string.max': 'Last name cannot exceed 50 characters'
      }),
    role: Joi.string()
      .valid('executive', 'finance', 'operations', 'procurement', 'manager', 'analyst')
      .default('analyst'),
    department: Joi.string()
      .valid('finance', 'operations', 'procurement', 'it', 'hr', 'sales', 'marketing')
      .required()
      .messages({
        'any.only': 'Department must be one of: finance, operations, procurement, it, hr, sales, marketing'
      })
  });

  return schema.validate(data);
};

// User login validation
const validateLogin = (data) => {
  const schema = Joi.object({
    email: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address'
      }),
    password: Joi.string()
      .required()
      .messages({
        'string.empty': 'Password is required'
      }),
    mfaToken: Joi.string()
      .pattern(/^[0-9]{6}$/)
      .optional()
      .messages({
        'string.pattern.base': 'MFA token must be a 6-digit number'
      })
  });

  return schema.validate(data);
};

// Financial data validation
const validateFinancialData = (data) => {
  const schema = Joi.object({
    period: Joi.object({
      year: Joi.number()
        .integer()
        .min(2020)
        .max(2030)
        .required()
        .messages({
          'number.min': 'Year must be 2020 or later',
          'number.max': 'Year cannot exceed 2030'
        }),
      month: Joi.number()
        .integer()
        .min(1)
        .max(12)
        .required()
        .messages({
          'number.min': 'Month must be between 1 and 12',
          'number.max': 'Month must be between 1 and 12'
        }),
      quarter: Joi.number()
        .integer()
        .min(1)
        .max(4)
        .optional()
    }).required(),
    department: Joi.string()
      .valid('finance', 'operations', 'procurement', 'it', 'hr', 'sales', 'marketing')
      .required()
      .messages({
        'any.only': 'Department must be one of: finance, operations, procurement, it, hr, sales, marketing'
      }),
    category: Joi.string()
      .valid('revenue', 'expenses', 'capital', 'operational')
      .required()
      .messages({
        'any.only': 'Category must be one of: revenue, expenses, capital, operational'
      }),
    subcategory: Joi.string()
      .min(1)
      .max(100)
      .required()
      .messages({
        'string.min': 'Subcategory is required',
        'string.max': 'Subcategory cannot exceed 100 characters'
      }),
    budgetAmount: Joi.number()
      .min(0)
      .required()
      .messages({
        'number.min': 'Budget amount must be non-negative'
      }),
    actualAmount: Joi.number()
      .min(0)
      .required()
      .messages({
        'number.min': 'Actual amount must be non-negative'
      }),
    currency: Joi.string()
      .valid('USD', 'EUR', 'GBP', 'CAD', 'AUD')
      .default('USD'),
    description: Joi.string()
      .max(500)
      .optional()
      .messages({
        'string.max': 'Description cannot exceed 500 characters'
      }),
    tags: Joi.array()
      .items(Joi.string().max(50))
      .max(10)
      .optional()
      .messages({
        'array.max': 'Cannot have more than 10 tags'
      }),
    status: Joi.string()
      .valid('draft', 'pending', 'approved', 'rejected')
      .default('draft')
  });

  return schema.validate(data);
};

// Report generation validation
const validateReportRequest = (data) => {
  const schema = Joi.object({
    type: Joi.string()
      .valid('budget_vs_actual', 'cash_flow', 'variance_analysis', 'department_summary', 'compliance')
      .required()
      .messages({
        'any.only': 'Report type must be one of: budget_vs_actual, cash_flow, variance_analysis, department_summary, compliance'
      }),
    period: Joi.object({
      startYear: Joi.number().integer().min(2020).required(),
      endYear: Joi.number().integer().min(2020).required(),
      startMonth: Joi.number().integer().min(1).max(12).optional(),
      endMonth: Joi.number().integer().min(1).max(12).optional()
    }).required(),
    filters: Joi.object({
      departments: Joi.array().items(
        Joi.string().valid('finance', 'operations', 'procurement', 'it', 'hr', 'sales', 'marketing')
      ).optional(),
      categories: Joi.array().items(
        Joi.string().valid('revenue', 'expenses', 'capital', 'operational')
      ).optional(),
      minAmount: Joi.number().min(0).optional(),
      maxAmount: Joi.number().min(0).optional()
    }).optional(),
    format: Joi.string()
      .valid('pdf', 'excel', 'csv', 'json')
      .default('pdf'),
    includeCharts: Joi.boolean().default(true),
    includeDetails: Joi.boolean().default(false)
  });

  return schema.validate(data);
};

// User update validation
const validateUserUpdate = (data) => {
  const schema = Joi.object({
    firstName: Joi.string()
      .min(1)
      .max(50)
      .optional(),
    lastName: Joi.string()
      .min(1)
      .max(50)
      .optional(),
    email: Joi.string()
      .email()
      .optional(),
    role: Joi.string()
      .valid('executive', 'finance', 'operations', 'procurement', 'manager', 'analyst')
      .optional(),
    department: Joi.string()
      .valid('finance', 'operations', 'procurement', 'it', 'hr', 'sales', 'marketing')
      .optional(),
    isActive: Joi.boolean().optional(),
    reportPreferences: Joi.object({
      frequency: Joi.string().valid('daily', 'weekly', 'monthly', 'quarterly').optional(),
      format: Joi.string().valid('pdf', 'excel', 'csv').optional(),
      deliveryMethod: Joi.string().valid('email', 'dashboard').optional()
    }).optional()
  });

  return schema.validate(data);
};

// Password change validation
const validatePasswordChange = (data) => {
  const schema = Joi.object({
    currentPassword: Joi.string()
      .required()
      .messages({
        'string.empty': 'Current password is required'
      }),
    newPassword: Joi.string()
      .min(8)
      .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])'))
      .required()
      .messages({
        'string.min': 'New password must be at least 8 characters long',
        'string.pattern.base': 'New password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'
      }),
    confirmPassword: Joi.string()
      .valid(Joi.ref('newPassword'))
      .required()
      .messages({
        'any.only': 'Password confirmation does not match new password'
      })
  });

  return schema.validate(data);
};

// Query parameters validation
const validateQueryParams = (data) => {
  const schema = Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(50),
    sortBy: Joi.string().default('updatedAt'),
    sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
    department: Joi.string().valid('finance', 'operations', 'procurement', 'it', 'hr', 'sales', 'marketing').optional(),
    year: Joi.number().integer().min(2020).max(2030).optional(),
    month: Joi.number().integer().min(1).max(12).optional(),
    quarter: Joi.number().integer().min(1).max(4).optional(),
    category: Joi.string().valid('revenue', 'expenses', 'capital', 'operational').optional(),
    status: Joi.string().valid('draft', 'pending', 'approved', 'rejected').optional(),
    minAmount: Joi.number().min(0).optional(),
    maxAmount: Joi.number().min(0).optional(),
    startDate: Joi.date().optional(),
    endDate: Joi.date().optional()
  });

  return schema.validate(data);
};

module.exports = {
  validateRegistration,
  validateLogin,
  validateFinancialData,
  validateReportRequest,
  validateUserUpdate,
  validatePasswordChange,
  validateQueryParams
};