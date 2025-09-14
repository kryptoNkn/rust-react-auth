import React, { useState } from "react";
import s from "./PasswordInput.module.scss";

interface PasswordInputProps {
  name: string;
  value: string;
  placeholder?: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
}

export default function PasswordInput({ name, value, placeholder, onChange }: PasswordInputProps) {
  const [show, setShow] = useState(false);

  return (
    <div className={s.passwordWrapper}>
      <input
        name={name}
        type={show ? "text" : "password"}
        placeholder={placeholder}
        value={value}
        onChange={onChange}
        className={s.input}
      />
      <button
        type="button"
        className={s.toggleBtn}
        onClick={() => setShow(!show)}
      >
        {show ? "Hide" : "Show"}
      </button>
    </div>
  );
}
