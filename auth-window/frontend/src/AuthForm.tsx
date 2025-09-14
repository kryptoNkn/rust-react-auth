import React, { useState } from "react";
import axios from "axios";
import { ToastContainer, toast } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';
import PasswordInput from "./PasswordInput";
import s from './AuthForm.module.scss';

interface RegisterData {
  username: string;
  email: string;
  password: string;
  confirmPassword: string;
}

interface LoginData {
  email: string;
  password: string;
}

const api = axios.create({
  baseURL: "http://localhost:8080",
  withCredentials: true,
});

export default function AuthForm() {
  const [isLogin, setIsLogin] = useState(true);
  const [registerForm, setRegisterForm] = useState<RegisterData>({
    username: "",
    email: "",
    password: "",
    confirmPassword: ""
  });
  const [loginForm, setLoginForm] = useState<LoginData>({
    email: "",
    password: ""
  });
  const [loading, setLoading] = useState(false);

  const isValidEmail = (email: string) =>
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    if (isLogin) {
      setLoginForm(prev => ({ ...prev, [name]: value }));
    } else {
      setRegisterForm(prev => ({ ...prev, [name]: value }));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (isLogin) {
        if (!isValidEmail(loginForm.email.trim())) throw new Error("Incorrect email.");
        if (loginForm.password.length < 6) throw new Error("Password must be at least 6 characters.");

        const res = await api.post("/login", {
          email: loginForm.email.trim(),
          password: loginForm.password,
        });
        toast.success(res.data.message);
        setLoginForm({ email: "", password: "" });

      } else {
        const { username, email, password, confirmPassword } = registerForm;
        if (username.trim().length < 3) throw new Error("Username must be at least 3 characters.");
        if (!isValidEmail(email.trim())) throw new Error("Incorrect email.");
        if (password.length < 6) throw new Error("Password must be at least 6 characters.");
        if (password !== confirmPassword) throw new Error("Passwords do not match.");

        const res = await api.post("/register", {
          username: username.trim(),
          email: email.trim(),
          password,
          confirm_password: confirmPassword,
        });

        toast.success(res.data.message);
        setRegisterForm({ username: "", email: "", password: "", confirmPassword: "" });
        setIsLogin(true);
      }
    } catch (err: any) {
      if (err.response?.data?.error) {
        toast.error(err.response.data.error);
      } else {
        toast.error(err.message || "Something went wrong.");
      }
    } finally {
      setLoading(false);
    }
  };

  const passwordsMatch = registerForm.password && registerForm.confirmPassword && registerForm.password === registerForm.confirmPassword;

  return (
    <>
      <div className={s.authWrapper}>
        <div className={s.toggleButtons}>
          <button className={isLogin ? s.active : ""} onClick={() => setIsLogin(true)}>Login</button>
          <button className={!isLogin ? s.active : ""} onClick={() => setIsLogin(false)}>Register</button>
        </div>

        <form onSubmit={handleSubmit} className={s.formContainer}>
          {isLogin ? (
            <>
              <h1>Sign In</h1>
              <input name="email" type="email" placeholder="Email" value={loginForm.email} onChange={handleChange} />
              <PasswordInput name="password" value={loginForm.password} placeholder="Password" onChange={handleChange} />
            </>
          ) : (
            <>
              <h1>Sign Up</h1>
              <input name="username" placeholder="Username" value={registerForm.username} onChange={handleChange} />
              <input name="email" type="email" placeholder="Email" value={registerForm.email} onChange={handleChange} />
              <PasswordInput name="password" value={registerForm.password} placeholder="Password" onChange={handleChange} />
              <PasswordInput name="confirmPassword" value={registerForm.confirmPassword} placeholder="Confirm Password" onChange={handleChange} />
              {registerForm.confirmPassword && (
                <p className={passwordsMatch ? s.successText : s.errorText}>
                  {passwordsMatch ? "Passwords match ✅" : "Passwords do not match ❌"}
                </p>
              )}
            </>
          )}
          <button type="submit" className={s.submitBtn} disabled={loading}>
            {loading ? (isLogin ? "Logging in..." : "Registering...") : (isLogin ? "Sign In" : "Sign Up")}
          </button>
        </form>
      </div>
      <ToastContainer position="top-right" autoClose={3000} />
    </>
  );
}
