import { useState } from "react";
import axios from "axios";
import { ToastContainer, toast } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';

export default function RegisterForm() {
  const [form, setForm] = useState({
    username: "",
    email: "",
    password: "",
    confirmPassword: ""
  });

  const isValidEmail = (email: string): boolean => {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const trimmedUsername = form.username.trim();
    const trimmedEmail = form.email.trim();

    if (trimmedUsername.length < 3) {
      toast.error("The name must be at least 3 characters long.");
      return;
    }

    if (!isValidEmail(trimmedEmail)) {
      toast.error("Incorrect email.");
      return;
    }

    if (form.password.length < 6) {
      toast.error("Password must be at least 6 characters long.");
      return;
    }

    if (form.password !== form.confirmPassword) {
      toast.error("The passwords do not match.");
      return;
    }

    try {
      const res = await axios.post("http://localhost:8080/register", {
        username: trimmedUsername,
        email: trimmedEmail,
        password: form.password
      });

      toast.success(res.data);

      setForm({ username: "", email: "", password: "", confirmPassword: "" });

    } catch (err: any) {
      toast.error(err.response?.data || "Registration error.");
    }
  };

  return (
    <>
      <form onSubmit={handleSubmit}>

        <input
          name="username"
          placeholder="Name"
          value={form.username}
          onChange={handleChange}
        />

        <input
          name="email"
          type="email"
          placeholder="Email"
          value={form.email}
          onChange={handleChange}
        />

        <input
          name="password"
          type="password"
          placeholder="Password"
          value={form.password}
          onChange={handleChange}
        />

        <input
          name="confirmPassword"
          type="password"
          placeholder="Repeat password"
          value={form.confirmPassword}
          onChange={handleChange}
        />

        <button type="submit">
          Register
        </button>
      </form>

      <ToastContainer position="top-right" autoClose={3000} />
    </>
  );
}