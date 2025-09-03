import { useState } from "react";
import axios from "axios";

export default function RegisterForm() {
  const [form, setForm] = useState({
    username: "",
    email: "",
    password: "",
    confirmPassword: ""
  });

  const [errors, setErrors] = useState({
    username: "",
    email: "",
    password: "",
    confirmPassword: "",
    server: ""
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
    setErrors({ ...errors, [e.target.name]: "", server: "" });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (form.username.trim().length < 3) {
      setErrors({ ...errors, username: "The name must be at least 3 characters long." });
      return;
    }

    if (!form.email.includes("@")) {
      setErrors({ ...errors, email: "Incorrect email." });
      return;
    }

    if (form.password.length < 6) {
      setErrors({ ...errors, password: "Password must be at least 6 characters long." });
      return;
    }

    if (form.password !== form.confirmPassword) {
      setErrors({ ...errors, confirmPassword: "The passwords do not match." });
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
      setErrors({ username: "", email: "", password: "", confirmPassword: "", server: "" });

    } catch (err: any) {
      setErrors({ ...errors, server: err.response?.data || "Registration error" });
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <input
          name="username"
          placeholder="Name"
          value={form.username}
          onChange={handleChange}
        />
        {errors.username && <p>{errors.username}</p>}
      </div>

      <div>
        <input
          name="email"
          type="email"
          placeholder="Email"
          value={form.email}
          onChange={handleChange}
        />
        {errors.email && <p>{errors.email}</p>}
      </div>

      <div>
        <input
          name="password"
          type="password"
          placeholder="Password"
          value={form.password}
          onChange={handleChange}
        />
        {errors.password && <p>{errors.password}</p>}
      </div>

      <div>
        <input
          name="confirmPassword"
          type="password"
          placeholder="Repeat password"
          value={form.confirmPassword}
          onChange={handleChange}
        />
        {errors.confirmPassword && <p>{errors.confirmPassword}</p>}
      </div>

      {errors.server && <p>{errors.server}</p>}

      <button type="submit">
        Register
      </button>
    </form>
  );
}
