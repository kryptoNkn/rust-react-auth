# Rust + React Auth App

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![Actix Web](https://img.shields.io/badge/Actix_Web-000000?style=for-the-badge&logo=rust&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)

Fullstack authentication and registration app built with **Rust + Actix Web** backend and **React + TypeScript** frontend, with **PostgreSQL database support**, secure JWT authentication, and brute-force protection.

---

## 📌 Features

- User registration with validation and **Argon2 password hashing**  
- Login with email and password  
- JWT token generation stored in **HttpOnly cookie** for secure authentication  
- Protected `/profile` route accessible only with a valid JWT token  
- **Brute-force protection**: limits login attempts per email  
- Database integration with PostgreSQL  
- Single frontend form (`AuthForm`) for login and registration  
- Logging of HTTP requests via Actix middleware  

---

## 🛠 Technologies

**Backend:** Rust, Actix Web, JWT, Argon2, Validator, UUID, dotenv, chrono, SQLx  
**Frontend:** React, TypeScript, Axios, React Toastify, SCSS  
**Database:** PostgreSQL (default)  

---

## ⚙️ Environment Variables

Create a `.env` file in the `backend` folder:

```env
DATABASE_URL=postgres://username:password@localhost/auth_db
JWT_SECRET=your_secret_key
```
---

### ✅ What's New / Changed

- Replaced in-memory storage with **PostgreSQL database**
- Added **JWT authentication via HttpOnly cookie**
- Added **brute-force login protection**
- Implemented **Argon2 password hashing and verification**
- Added **Actix middleware** for protected routes using JWT
- Frontend now works with **cookie-based authentication** instead of localStorage only

---

### 🔄 Authentication Flow

1. User fills the registration or login form on frontend.
2. Form data is sent via POST /register or /login to backend.
3. Backend validates input:
   - For registration: password match, hashing with Argon2
   - For login: checks email, password, brute-force attempts
4. Backend generates JWT token with user_id and expiry.
5. JWT token is stored in HttpOnly cookie `auth_token`.
6. For protected routes (like GET /profile):
   - Backend reads cookie
   - Decodes JWT and verifies signature
   - Fetches user from database if valid
7. Returns JSON with user info or error if token is invalid/missing.

---

## 📝 API Endpoints

### POST `/register`
Register a new user.

**Request body:**
```json
{
  "username": "john",
  "email": "john@example.com",
  "password": "123456",
  "confirm_password": "123456"
}
```

**Response (success):**
```json
{
  "message": "User john registered",
  "user_id": "uuid",
  "token": "jwt_token_here"
}
```

**Response (error, validation failed):**
```json
{
  "errors": {
    "email": [{"code": "email", "message": "Invalid email"}],
    "password": [{"code": "length", "message": "Password too short"}]
  }
}
```


### POST `/login`
Login with email and password.

**Request body:**
```json
{
  "email": "john@example.com",
  "password": "123456"
}
```

**Response (success):**
```json
{
  "message": "User john logged in",
  "user_id": "uuid",
  "token": "jwt_token_here"
}
```

**Response (error, invalid credentials):**
```json
{
  "error": "Invalid email or password"
}
```


### GET `/profile`

Get profile information (protected route).

**Response (success):**
```json
{
  "message": "Protected route",
  "user_id": "uuid"
}
```

**Response (error, missing or invalid token):**
```json
{
  "error": "Missing Authorization header"
}
```


## 🚀 Getting Started
### Backend
```bash
cd backend
cargo run
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

I created this project by combining my programming knowledge with help from ChatGPT.
