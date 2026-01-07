# Project Management Authentication Backend

Project Management Authentication Backend is a secure, scalable, and modular backend for user authentication built with Node.js, Express.js, MongoDB, and JWT.  
It implements modern authentication best practices including **JWT access & refresh tokens, email verification, logout, protected routes, cookie handling, and role-based design patterns.

📁 This is a **pure backend application** and serves as an authentication microservice for any project requiring user login and security.

---

## 📌 Features

### ✅ Core Authentication
- User registration with email verification
- Login with hashed passwords
- JWT access & refresh token generation
- Refresh token storage and revocation
- Logout and session invalidation

### 🔐 Token Handling
- Access tokens stored in **HTTP-only cookies**
- Refresh tokens stored securely in DB
- Protected routes guarded via JWT middleware

### 📏 Best Practices
- Modular project structure
- Async handler & centralized error handling
- Environment config using `.env`
- Validation with **express-validator**
- Nodemailer + Mailgen for clean email templates

---

## 🚀 Tech Stack

| Component | Technology |
|-----------|------------|
| Runtime | Node.js |
| Server | Express.js |
| Database | MongoDB |
| Authentication | JWT (Access + Refresh tokens) |
| Emails | Nodemailer + Mailgen |
| Validation | express-validator |
| Code Quality | Prettier, Async error handler |
| Environment | dotenv |

---

## 📁 Folder Structure
📦Project-management-authentication-backend
┣ 📂src
┃ ┣ 📂controllers
┃ ┣ 📂middlewares
┃ ┣ 📂models
┃ ┣ 📂routes
┃ ┗ 📂utils
┣ .env
┣ .gitignore
┣ package.json
┣ README.md

---


## 📝 Installation & Setup

### 1️⃣ Clone the repository
```bash
Clone the project 
git clone https://github.com/ManikanthGaddam/Project-management-authentication-backend.git
cd Project-management-authentication-backend

Install packages
npm install

Create .env file
PORT=3000
MONGO_URI=your_mongo_connection_string
ACCESS_TOKEN_SECRET=your_jwt_access_secret
REFRESH_TOKEN_SECRET=your_jwt_refresh_secret
MAILTRAP_HOST=sandbox.smtp.mailtrap.io
MAILTRAP_PORT=2525
MAILTRAP_USERNAME=your_mailtrap_user
MAILTRAP_PASSWORD=your_mailtrap_pass

Run the server
npm run dev
```

