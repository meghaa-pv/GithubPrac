const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
  role: {
    type: String,
    enum: ['executive', 'finance', 'operations', 'procurement', 'manager', 'analyst'],
    required: true,
    default: 'analyst'
  },
  department: {
    type: String,
    enum: ['finance', 'operations', 'procurement', 'it', 'hr', 'sales', 'marketing'],
    required: true
  },
  permissions: [{
    resource: {
      type: String,
      enum: ['budgets', 'actuals', 'cashflow', 'reports', 'audit', 'admin']
    },
    actions: [{
      type: String,
      enum: ['read', 'write', 'delete', 'approve']
    }]
  }],
  mfaEnabled: {
    type: Boolean,
    default: false
  },
  mfaSecret: {
    type: String,
    default: null
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  reportPreferences: {
    frequency: {
      type: String,
      enum: ['daily', 'weekly', 'monthly', 'quarterly'],
      default: 'monthly'
    },
    format: {
      type: String,
      enum: ['pdf', 'excel', 'csv'],
      default: 'pdf'
    },
    deliveryMethod: {
      type: String,
      enum: ['email', 'dashboard'],
      default: 'email'
    }
  }
}, {
  timestamps: true
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });
userSchema.index({ department: 1 });

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const rounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
    this.password = await bcrypt.hash(this.password, rounds);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to check password
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Method to increment login attempts
userSchema.methods.incLoginAttempts = function() {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = {
      lockUntil: Date.now() + 2 * 60 * 60 * 1000 // 2 hours
    };
  }
  
  return this.updateOne(updates);
};

// Method to check permissions
userSchema.methods.hasPermission = function(resource, action) {
  const permission = this.permissions.find(p => p.resource === resource);
  return permission && permission.actions.includes(action);
};

// Static method to get role permissions
userSchema.statics.getRolePermissions = function(role) {
  const rolePermissions = {
    executive: [
      { resource: 'budgets', actions: ['read', 'approve'] },
      { resource: 'actuals', actions: ['read'] },
      { resource: 'cashflow', actions: ['read'] },
      { resource: 'reports', actions: ['read'] },
      { resource: 'audit', actions: ['read'] }
    ],
    finance: [
      { resource: 'budgets', actions: ['read', 'write', 'approve'] },
      { resource: 'actuals', actions: ['read', 'write'] },
      { resource: 'cashflow', actions: ['read', 'write'] },
      { resource: 'reports', actions: ['read', 'write'] },
      { resource: 'audit', actions: ['read'] }
    ],
    operations: [
      { resource: 'budgets', actions: ['read'] },
      { resource: 'actuals', actions: ['read'] },
      { resource: 'reports', actions: ['read'] }
    ],
    procurement: [
      { resource: 'budgets', actions: ['read'] },
      { resource: 'actuals', actions: ['read'] },
      { resource: 'reports', actions: ['read'] }
    ],
    manager: [
      { resource: 'budgets', actions: ['read', 'write'] },
      { resource: 'actuals', actions: ['read', 'write'] },
      { resource: 'reports', actions: ['read', 'write'] }
    ],
    analyst: [
      { resource: 'budgets', actions: ['read'] },
      { resource: 'actuals', actions: ['read'] },
      { resource: 'reports', actions: ['read'] }
    ]
  };
  
  return rolePermissions[role] || [];
};

module.exports = mongoose.model('User', userSchema);