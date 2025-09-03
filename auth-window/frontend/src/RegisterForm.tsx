import { useState } from "react";
import axios from "axios";

export default function RegisterForm() {
  const [form, setForm] = useState({
    username: "",
    email: "",
    password: "",
    confirmPassword: ""
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (form.password !== form.confirmPassword) {
      alert("The passwords do not match");
      return;
    }

    try {
      const res = await axios.post("http://localhost:8080/register", {
        username: form.username,
        email: form.email,
        password: form.password
      });

      alert(res.data);
      setForm({ username: "", email: "", password: "", confirmPassword: "" });
    } catch (err: any) {
      alert(err.response?.data || "Registration error");
    }
  };

  return (
    <form onSubmit={handleSubmit} >
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
  );
}