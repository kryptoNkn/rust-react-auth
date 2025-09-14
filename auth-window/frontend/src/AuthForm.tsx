import React, { useState } from "react";
import axios from "axios";
import { ToastContainer, toast } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';
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
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const isValidEmail = (email: string) =>
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    if (isLogin) {
      setLoginForm({ ...loginForm, [name]: value });
    } else {
      setRegisterForm({ ...registerForm, [name]: value });
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (isLogin) {
        const trimmedEmail = loginForm.email.trim();
        if (!isValidEmail(trimmedEmail)) { toast.error("Incorrect email."); setLoading(false); return; }
        if (loginForm.password.length < 6) { toast.error("Password must be at least 6 characters."); setLoading(false); return; }

        const res = await axios.post("http://localhost:8080/login", { email: trimmedEmail, password: loginForm.password });
        toast.success(res.data.message);
        localStorage.setItem("token", res.data.token);
        setLoginForm({ email: "", password: "" });

      } else {
        const trimmedUsername = registerForm.username.trim();
        const trimmedEmail = registerForm.email.trim();
        if (trimmedUsername.length < 3) { toast.error("Name must be at least 3 characters."); setLoading(false); return; }
        if (!isValidEmail(trimmedEmail)) { toast.error("Incorrect email."); setLoading(false); return; }
        if (registerForm.password.length < 6) { toast.error("Password must be at least 6 characters."); setLoading(false); return; }
        if (registerForm.password !== registerForm.confirmPassword) { toast.error("Passwords do not match."); setLoading(false); return; }

        const res = await axios.post("http://localhost:8080/register", {
          username: trimmedUsername,
          email: trimmedEmail,
          password: registerForm.password,
          confirm_password: registerForm.confirmPassword, // теперь точно совпадает с Rust
        });

        toast.success(res.data.message);
        localStorage.setItem("token", res.data.token);
        setRegisterForm({ username: "", email: "", password: "", confirmPassword: "" });
        setIsLogin(true);
      }

    } catch (err: any) {
      if (err.response?.data?.errors) {
        const messages = Object.entries(err.response.data.errors).map(([key, val]) => `${key}: ${JSON.stringify(val)}`);
        toast.error(messages.join("\n"));
      } else if (err.response?.data?.error) {
        toast.error(err.response.data.error);
      } else {
        toast.error("Something went wrong.");
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
              <div className={s.passwordWrapper}>
                <input name="password" type={showPassword ? "text" : "password"} placeholder="Password" value={loginForm.password} onChange={handleChange} />
                <button type="button" onClick={() => setShowPassword(!showPassword)}>{showPassword ? "Hide" : "Show"}</button>
              </div>
            </>
          ) : (
            <>
              <h1>Sign Up</h1>
              <input name="username" placeholder="Username" value={registerForm.username} onChange={handleChange} />
              <input name="email" type="email" placeholder="Email" value={registerForm.email} onChange={handleChange} />
              <div className={s.passwordWrapper}>
                <input name="password" type={showPassword ? "text" : "password"} placeholder="Password" value={registerForm.password} onChange={handleChange} />
                <button type="button" onClick={() => setShowPassword(!showPassword)}>{showPassword ? "Hide" : "Show"}</button>
              </div>
              <div className={s.passwordWrapper}>
                <input name="confirmPassword" type={showConfirmPassword ? "text" : "password"} placeholder="Confirm Password" value={registerForm.confirmPassword} onChange={handleChange} />
                <button type="button" onClick={() => setShowConfirmPassword(!showConfirmPassword)}>{showConfirmPassword ? "Hide" : "Show"}</button>
              </div>
              {registerForm.confirmPassword && (
                <p className={passwordsMatch ? s.successText : s.errorText}>{passwordsMatch ? "Passwords match ✅" : "Passwords do not match ❌"}</p>
              )}
            </>
          )}
          <button type="submit" className={s.submitBtn} disabled={loading}>{loading ? (isLogin ? "Logging in..." : "Registering...") : (isLogin ? "Sign In" : "Sign Up")}</button>
        </form>
      </div>
      <ToastContainer position="top-right" autoClose={3000} />
    </>
  );
}
