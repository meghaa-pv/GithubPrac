# Enterprise Financial Analytics Platform

A centralized, secure, role-based analytics platform that integrates financial data across departments, delivers real-time insights, and automates compliance monitoring.

## 🚀 Key Features

### 1. Executive Dashboard
- **Real-time budget vs actuals** with variance analysis
- **Cash flow visualizations** showing monthly trends
- **Automated alerts** for budget overruns and anomalies
- **Department summaries** with drill-down capabilities
- **Key performance indicators** and financial metrics

### 2. Role-Based Departmental Views
- **Custom dashboards** for Finance, Operations, Procurement, IT, HR, Sales, Marketing
- **Department-specific access control** ensuring data security
- **Drill-down capabilities** to transaction-level details
- **Monthly trends** and category breakdowns
- **Upcoming budget items** and approval workflows

### 3. Automated Report Generator
- **Multiple report types**: Budget vs Actual, Cash Flow, Variance Analysis, Department Summary, Compliance
- **Exportable formats**: PDF, Excel, CSV, JSON
- **Configurable filters** by department, category, date range, amount
- **Scheduled delivery** to stakeholders via email
- **Report history** and audit trails

### 4. Audit Log & Compliance Tracker
- **Comprehensive audit logging** of all data modifications and access
- **Real-time security alerts** for unauthorized access attempts
- **Compliance reporting** for SOX, GDPR, and financial regulations
- **Automated notifications** for policy violations
- **7-year data retention** for compliance requirements

### 5. Advanced Security Features
- **Multi-factor authentication (MFA)** with TOTP support
- **Role-based access control** with granular permissions
- **JWT-based authentication** with secure token management
- **Rate limiting** and DDoS protection
- **Input validation** and SQL injection prevention
- **Comprehensive audit trails** for all user actions

## 🏗️ Architecture

### Backend (Node.js/Express)
```
server/
├── models/           # Database schemas (User, FinancialData, AuditLog)
├── routes/           # API endpoints
├── middleware/       # Authentication, authorization, audit logging
├── utils/           # Validation and report generation utilities
└── index.js         # Main server file
```

### Database (MongoDB)
- **Users Collection**: Role-based access control, MFA settings
- **Financial Data Collection**: Budget/actual data with approval workflows
- **Audit Logs Collection**: Comprehensive compliance tracking

### Security Layers
1. **Application Security**: Helmet, CORS, rate limiting
2. **Authentication**: JWT with MFA support
3. **Authorization**: Role-based permissions system
4. **Data Security**: Input validation, audit logging
5. **Compliance**: SOX, GDPR compliance features

## 🛠️ Installation & Setup

### Prerequisites
- Node.js 16+ and npm
- MongoDB 4.4+
- Git

### Quick Start

1. **Clone the repository**
```bash
git clone <repository-url>
cd enterprise-financial-analytics
```

2. **Install dependencies**
```bash
npm run install-all
```

3. **Environment Setup**
```bash
# Copy environment template
cp server/.env.example server/.env

# Edit server/.env with your configuration:
MONGODB_URI=mongodb://localhost:27017/financial_analytics
JWT_SECRET=your_secure_random_string_here
MFA_SECRET_KEY=your_mfa_secret_here
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@company.com
SMTP_PASS=your_app_password
```

4. **Start MongoDB**
```bash
# Using MongoDB Community Edition
mongod --dbpath /path/to/your/db

# Or using Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

5. **Start the application**
```bash
# Development mode (runs both server and client)
npm run dev

# Or start server only
npm run server
```

6. **Initial Admin Access**
- **Email**: admin@company.com
- **Password**: Admin123!
- **Role**: Executive (full access)

The server will start on `http://localhost:5000`

## 📊 API Documentation

### Authentication Endpoints
```
POST /api/auth/register    # Register new user
POST /api/auth/login       # User login (with MFA support)
POST /api/auth/logout      # User logout
GET  /api/auth/me          # Get current user info
POST /api/auth/setup-mfa   # Setup multi-factor authentication
POST /api/auth/verify-mfa  # Verify and enable MFA
POST /api/auth/disable-mfa # Disable MFA
```

### Financial Data Endpoints
```
GET    /api/financial-data     # Get financial data with filters
POST   /api/financial-data     # Create new financial record
GET    /api/financial-data/:id # Get specific record
PUT    /api/financial-data/:id # Update record
DELETE /api/financial-data/:id # Soft delete record
POST   /api/financial-data/bulk        # Bulk operations
POST   /api/financial-data/:id/approve # Approve record
```

### Dashboard Endpoints
```
GET /api/dashboard/executive           # Executive dashboard data
GET /api/dashboard/department/:dept    # Department-specific dashboard
GET /api/dashboard/alerts             # All alerts and notifications
GET /api/dashboard/metrics            # Key financial metrics
```

### Reports Endpoints
```
POST /api/reports/generate    # Generate financial report
POST /api/reports/export      # Export report in specified format
POST /api/reports/schedule    # Schedule recurring report
GET  /api/reports/scheduled   # Get scheduled reports
GET  /api/reports/history     # Report generation history
```

### Audit & Compliance Endpoints
```
GET /api/audit/logs              # Get audit logs with filters
GET /api/audit/security-alerts   # Security alerts
GET /api/audit/compliance        # Compliance reporting
```

## 👥 Role-Based Access Control

### Executive
- **Full system access** across all departments
- **Approve high-value transactions** (unlimited)
- **Access all reports** and audit logs
- **Manage user permissions**

### Finance
- **Cross-department visibility** for financial oversight
- **Approve transactions** up to $100,000
- **Generate and export** all report types
- **Access audit logs** for compliance

### Manager
- **Department-specific access** with limited cross-department visibility
- **Approve transactions** up to $10,000
- **Generate departmental reports**
- **Modify departmental budgets**

### Operations/Procurement/IT/HR/Sales/Marketing
- **Department-specific access only**
- **View-only permissions** for budgets and actuals
- **Generate departmental reports**
- **Cannot approve transactions**

### Analyst
- **Read-only access** to assigned department data
- **Basic reporting capabilities**
- **Cannot modify financial data**
- **Approval threshold**: $1,000

## 🔒 Security Features

### Authentication & Authorization
- **JWT-based authentication** with configurable expiration
- **Multi-factor authentication** using TOTP (Google Authenticator compatible)
- **Account lockout** after 5 failed login attempts
- **Role-based permissions** with granular resource access control
- **Session management** with secure token handling

### Data Protection
- **Input validation** using Joi schemas
- **SQL injection prevention** with parameterized queries
- **XSS protection** with Content Security Policy
- **Rate limiting** to prevent brute force attacks
- **CORS configuration** for cross-origin request security

### Audit & Compliance
- **Comprehensive audit logging** of all user actions
- **Real-time security monitoring** and alerting
- **Compliance reporting** for SOX, GDPR requirements
- **Data retention policies** (7-year retention for audit logs)
- **Automated compliance scoring** and violation detection

### Infrastructure Security
- **Helmet.js** for security headers
- **Request rate limiting** (100 requests per 15 minutes)
- **IP-based tracking** for security monitoring
- **Graceful error handling** without information leakage
- **Environment-based configuration** for sensitive data

## 📈 Monitoring & Alerts

### Real-time Alerts
- **Budget overruns** exceeding defined thresholds
- **Variance alerts** for significant budget vs actual differences
- **Security alerts** for unauthorized access attempts
- **High-value transaction alerts** requiring review
- **Compliance violations** automatically flagged

### Dashboard Metrics
- **Budget utilization** percentages by department
- **Cash flow trends** with monthly comparisons
- **Variance analysis** highlighting significant deviations
- **Department performance** summaries
- **Recent activity** feeds for transparency

## 🚀 Production Deployment

### Environment Variables
```bash
NODE_ENV=production
PORT=5000
MONGODB_URI=mongodb://your-production-db/financial_analytics
JWT_SECRET=your-production-jwt-secret
MFA_SECRET_KEY=your-production-mfa-secret
SMTP_HOST=your-smtp-server
SMTP_PORT=587
SMTP_USER=your-production-email
SMTP_PASS=your-production-password
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
BCRYPT_ROUNDS=12
```

### Docker Deployment
```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 5000
CMD ["npm", "start"]
```

### MongoDB Indices
The application automatically creates necessary indices for optimal performance:
- User email and role indices
- Financial data period and department indices
- Audit log timestamp and action indices

## 📋 API Examples

### Authentication
```bash
# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@company.com","password":"Admin123!"}'

# Get current user (requires Authorization header)
curl -X GET http://localhost:5000/api/auth/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Financial Data
```bash
# Create financial record
curl -X POST http://localhost:5000/api/financial-data \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "period": {"year": 2024, "month": 1},
    "department": "finance",
    "category": "expenses",
    "subcategory": "Software Licenses",
    "budgetAmount": 50000,
    "actualAmount": 45000,
    "description": "Annual software licensing costs"
  }'

# Get financial data with filters
curl -X GET "http://localhost:5000/api/financial-data?year=2024&department=finance" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Reports
```bash
# Generate budget vs actual report
curl -X POST http://localhost:5000/api/reports/generate \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "budget_vs_actual",
    "period": {"startYear": 2024, "endYear": 2024, "startMonth": 1, "endMonth": 12},
    "filters": {"departments": ["finance", "operations"]},
    "format": "json"
  }'
```

## 🧪 Testing

### Run Tests
```bash
# Backend tests
cd server && npm test

# Integration tests
npm run test:integration

# Security tests
npm run test:security
```

### Test Coverage
- **Unit tests** for all models and utilities
- **Integration tests** for API endpoints
- **Security tests** for authentication and authorization
- **Load tests** for performance validation

## 📚 Additional Resources

### Documentation
- [API Reference](docs/api-reference.md)
- [Security Guide](docs/security.md)
- [Deployment Guide](docs/deployment.md)
- [User Manual](docs/user-manual.md)

### Support
- **Email**: support@yourcompany.com
- **Slack**: #financial-analytics
- **Documentation**: https://docs.yourcompany.com/financial-api

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 🎯 Roadmap

- [ ] **Q1 2024**: Mobile app development
- [ ] **Q2 2024**: Advanced ML-based forecasting
- [ ] **Q3 2024**: Real-time data streaming
- [ ] **Q4 2024**: Advanced visualization dashboard

---

**Built with ❤️ for enterprise financial transparency and data-driven decision making.**