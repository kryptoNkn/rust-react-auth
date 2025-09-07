# Rust + React Auth App

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![Actix Web](https://img.shields.io/badge/Actix_Web-000000?style=for-the-badge&logo=rust&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)

A fullstack authentication and registration app built with **Rust + Actix Web** for the backend and **React + TypeScript** for the frontend.

---

## 📌 Features

- User registration with validation and password hashing  
- Login with email and password  
- JWT token generation for authentication  
- Protected `/profile` route, accessible only with a valid token  
- In-memory storage (with database integration ready)  
- Single frontend form (`AuthForm`) for login and registration  
- Token temporarily stored in `localStorage`  

---

## 🛠 Technologies

**Backend:** Rust, Actix Web, JWT, Argon2, Validator, UUID, dotenv, chrono  
**Frontend:** React, TypeScript, Axios, React Toastify, SCSS  
**Database:** Currently in-memory; can be swapped with SQLite, Postgres, or other DB  

---

## ⚙️ Environment Variables

Create a `.env` file in the `backend` folder:

```env
JWT_SECRET=your_secret_key
```


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
I plan to periodically improve it by adding new features such as refresh tokens, database integration, user roles, and a more advanced UI.
