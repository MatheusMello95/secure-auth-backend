# 🔐 Secure Auth Backend

A comprehensive authentication system built with Laravel that provides secure user authentication, two-factor authentication (2FA), session management, and admin functionality.

## ✨ Features

- **🛡️ Secure Authentication** - User login/logout with Laravel Sanctum
- **🔑 Two-Factor Authentication (2FA)** - TOTP-based 2FA with QR codes and backup codes
- **📱 Session Management** - View and terminate active sessions across devices
- **🔄 Password Reset** - Secure password reset functionality via email
- **👨‍💼 Admin Panel** - User management for administrators
- **🚀 API-First Design** - RESTful API endpoints for frontend integration
- **🔒 Security Headers** - CSRF protection and secure session handling

## 📋 Prerequisites

Before setting up the project, ensure you have the following installed:

- **PHP 8.2 or higher**
- **Composer** (Dependency Manager for PHP)
- **Node.js 18+** and npm (for the frontend)
- **Database** (SQLite is used by default, but MySQL/PostgreSQL supported)
- **Web Server** (Apache/Nginx or use `php artisan serve`)

## 🚀 Installation & Setup

### Step 1: Clone the Repository

```bash
git clone <your-repository-url>
cd secure-auth-backend
```

### Step 2: Install PHP Dependencies

```bash
composer install
```

This will install all Laravel dependencies including:
- Laravel Framework 12.0
- Laravel Sanctum (API authentication)
- Google2FA (Two-factor authentication)
- Bacon QR Code (QR code generation)

### Step 3: Environment Configuration

1. Copy the environment file:
```bash
cp .env.example .env
```

2. Generate application key:
```bash
php artisan key:generate
```

3. Configure your `.env` file with the following important settings:

```env
APP_NAME="Secure Auth Backend"
APP_ENV=local
APP_KEY=base64:your-generated-key
APP_DEBUG=true
APP_URL=http://localhost:8000

# Database Configuration (SQLite )
# DB_CONNECTION=sqlite
# DB_DATABASE=database/database.sqlite

# For MySQL (optional)
# DB_CONNECTION=mysql
# DB_HOST=127.0.0.1
# DB_PORT=3306
# DB_DATABASE=secure_auth
# DB_USERNAME=root
# DB_PASSWORD=

DB_CONNECTION=pgsql
DB_HOST=127.0.0.1
DB_PORT=5432
DB_DATABASE=secure_auth
DB_USERNAME=root
DB_PASSWORD=

# Frontend URL (for password reset emails)
FRONTEND_URL=http://localhost:3000

# Session Configuration
SESSION_DRIVER=database
SESSION_LIFETIME=120
SESSION_ENCRYPT=true

# Mail Configuration (for password reset)
MAIL_MAILER=smtp
MAIL_HOST=your-smtp-host
MAIL_PORT=587
MAIL_USERNAME=your-email
MAIL_PASSWORD=your-password
MAIL_ENCRYPTION=tls
MAIL_FROM_ADDRESS=noreply@yourapp.com
MAIL_FROM_NAME="${APP_NAME}"
```

### Step 4: Database Setup

1. Run database migrations:
```bash
php artisan migrate
```

This will create the necessary tables:
- `users` - User accounts
- `sessions` - Session management
- `password_reset_tokens` - Password reset functionality
- `personal_access_tokens` - Sanctum API tokens

### Step 5: Seed Database (Optional)

Create a test admin user:
```bash
php artisan db:seed
```

### Step 6: Frontend Setup

> **Important:** This backend requires the `secure-auth-frontend` repository to function properly.

1. Clone and setup the frontend in a separate directory:
```bash
git clone https://github.com/MatheusMello95/secure-auth-fronten.git
cd secure-auth-frontend
npm install
```

2. Configure frontend environment variables:
```env
NEXT_PUBLIC_API_URL=http://localhost:8000/api
```

### Step 7: Start the Development Servers

1. Start the Laravel backend:
```bash
php artisan serve
```
The API will be available at `http://localhost:8000`

2. In a separate terminal, start the Next.js frontend:
```bash
cd secure-auth-frontend
npm run dev
```
The frontend will be available at `http://localhost:3000`

## 📚 API Endpoints

### Public Routes

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/login` | User authentication |
| `GET` | `/api/csrf-token` | Get CSRF token |
| `POST` | `/api/verify-2fa` | Verify 2FA code |
| `POST` | `/api/verify-backup-code` | Verify 2FA backup code |
| `POST` | `/api/password/reset-request` | Request password reset |
| `POST` | `/api/password/reset` | Reset password |

### Protected Routes (Require Authentication)

#### Authentication & Session Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/logout` | Logout current session |
| `POST` | `/api/logout-all` | Logout all sessions |
| `GET` | `/api/sessions` | Get active sessions |
| `DELETE` | `/api/sessions/{id}` | Terminate specific session |
| `DELETE` | `/api/sessions` | Terminate all sessions |

#### Two-Factor Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/2fa/setup` | Setup 2FA (get QR code) |
| `POST` | `/api/2fa/verify` | Verify 2FA setup |
| `GET` | `/api/2fa/status` | Check 2FA status |
| `POST` | `/api/2fa/disable` | Disable 2FA |
| `GET` | `/api/2fa/recovery-codes` | Get recovery codes |
| `POST` | `/api/2fa/recovery-codes` | Regenerate recovery codes |

#### User Management (Admin Only)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/users` | List users |
| `POST` | `/api/users` | Create user |
| `GET` | `/api/users/{id}` | Get user details |
| `PUT` | `/api/users/{id}` | Update user |
| `DELETE` | `/api/users/{id}` | Delete user |

## 🔧 Configuration

### Database Options

The system supports multiple database configurations:

- **SQLite** - Perfect for development and small deployments
- **MySQL** - For production environments
- **PostgreSQL** (Default) - For advanced features and scalability

### Security Features

- CSRF protection enabled by default
- Encrypted session storage
- Rate limiting on authentication endpoints
- Secure password hashing with bcrypt
- JWT tokens via Laravel Sanctum
