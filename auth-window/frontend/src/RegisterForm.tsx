import { useState } from "react";
import axios from "axios";
import { ToastContainer, toast } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';
import s from './RegisterForm.module.scss';

export default function RegisterForm() {
  const [form, setForm] = useState({ username: "", email: "", password: "", confirmPassword: "" });
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const isValidEmail = (email: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const trimmedUsername = form.username.trim();
    const trimmedEmail = form.email.trim();

    if (trimmedUsername.length < 3) { toast.error("Name must be at least 3 characters."); return; }
    if (!isValidEmail(trimmedEmail)) { toast.error("Incorrect email."); return; }
    if (form.password.length < 6) { toast.error("Password must be at least 6 characters."); return; }
    if (form.password !== form.confirmPassword) { toast.error("Passwords do not match."); return; }

    setLoading(true);
    try {
      const res = await axios.post("http://localhost:8080/register", {
        username: trimmedUsername,
        email: trimmedEmail,
        password: form.password
      });

      toast.success(res.data.message);
      localStorage.setItem("token", res.data.token);
      setForm({ username: "", email: "", password: "", confirmPassword: "" });

    } catch (err: any) {
      toast.error(err.response?.data?.errors ? JSON.stringify(err.response.data.errors) : "Registration error.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <form onSubmit={handleSubmit} className={s.formContainer}>
        <input name="username" placeholder="Name" value={form.username} onChange={handleChange} />
        <input name="email" type="email" placeholder="Email" value={form.email} onChange={handleChange} />

        <div className={s.passwordWrapper}>
          <input name="password" type={showPassword ? "text" : "password"} placeholder="Password" value={form.password} onChange={handleChange} />
          <button type="button" onClick={() => setShowPassword(!showPassword)}>{showPassword ? "Hide" : "Show"}</button>
        </div>

        <input name="confirmPassword" type="password" placeholder="Repeat password" value={form.confirmPassword} onChange={handleChange} />

        <button type="submit" className={s.submitBtn} disabled={loading}>
          {loading ? "Registering..." : "Register"}
        </button>
      </form>

      <ToastContainer position="top-right" autoClose={3000} />
    </>
  );
}
