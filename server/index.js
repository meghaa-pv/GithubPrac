require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

// Import routes
const authRoutes = require('./routes/auth');
const financialDataRoutes = require('./routes/financial-data');
const dashboardRoutes = require('./routes/dashboard');
const reportsRoutes = require('./routes/reports');
const auditRoutes = require('./routes/audit');

// Import middleware
const { auditLogger } = require('./middleware/audit');

// Create Express app
const app = express();

// Configure logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://yourdomain.com'] 
    : ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Trust proxy (important for getting real IP addresses when behind a proxy)
app.set('trust proxy', 1);

// Request logging middleware
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Audit logging middleware (for authenticated routes)
app.use('/api', auditLogger);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/financial-data', financialDataRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/reports', reportsRoutes);
app.use('/api/audit', auditRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

// API documentation endpoint
app.get('/api', (req, res) => {
  res.json({
    name: 'Enterprise Financial Analytics API',
    version: '1.0.0',
    description: 'Centralized, secure, role-based financial analytics platform',
    endpoints: {
      auth: '/api/auth',
      financialData: '/api/financial-data',
      dashboard: '/api/dashboard',
      reports: '/api/reports',
      audit: '/api/audit'
    },
    documentation: 'https://docs.yourcompany.com/financial-api'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(err.stack);
  
  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV !== 'production';
  
  res.status(err.status || 500).json({
    error: isDevelopment ? err.message : 'Internal server error',
    ...(isDevelopment && { stack: err.stack })
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    path: req.originalUrl,
    method: req.method
  });
});

// Database connection
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    logger.info(`MongoDB Connected: ${conn.connection.host}`);
    
    // Create initial admin user if none exists
    await createInitialAdminUser();
    
  } catch (error) {
    logger.error('Database connection error:', error);
    process.exit(1);
  }
};

// Create initial admin user for first-time setup
const createInitialAdminUser = async () => {
  try {
    const User = require('./models/User');
    const existingAdmin = await User.findOne({ role: 'executive' });
    
    if (!existingAdmin) {
      const adminUser = new User({
        username: 'admin',
        email: 'admin@company.com',
        password: 'Admin123!',
        firstName: 'System',
        lastName: 'Administrator',
        role: 'executive',
        department: 'finance',
        permissions: User.getRolePermissions('executive'),
        isActive: true
      });
      
      await adminUser.save();
      logger.info('Initial admin user created: admin@company.com / Admin123!');
    }
  } catch (error) {
    logger.error('Error creating initial admin user:', error);
  }
};

// Graceful shutdown
const gracefulShutdown = (signal) => {
  logger.info(`Received ${signal}. Shutting down gracefully...`);
  
  mongoose.connection.close(() => {
    logger.info('MongoDB connection closed.');
    process.exit(0);
  });
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start server
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  await connectDB();
  
  app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
    console.log(`🚀 Financial Analytics API Server started on port ${PORT}`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/api`);
    console.log(`🔐 Initial Admin: admin@company.com / Admin123!`);
  });
};

// Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
  logger.error('Unhandled Promise Rejection:', err);
  console.log('Shutting down the server due to Unhandled Promise rejection');
  process.exit(1);
});

startServer();

module.exports = app;