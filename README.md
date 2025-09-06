# Rust + React Auth App

This project is a small fullstack application for user authentication and registration.  
The backend is built with **Rust (Actix Web)**, and the frontend is built with **React + TypeScript**.  

## 📌 Features
- User registration (with validation, password hashing, and in-memory storage).  
- Login with email and password.  
- JWT token generation for authentication.  
- Protected `/profile` route, accessible only with a valid token.  
- Frontend with a single form (**AuthForm**) for both login and registration.  
- Token stored in `localStorage` (temporarily).  

## 🛠 Technologies
- **Backend**: Rust, Actix Web, JWT, Argon2, Validator, UUID, dotenv  
- **Frontend**: React, TypeScript, React Router, Axios, React Toastify, SCSS  

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
