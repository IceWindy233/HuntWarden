import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";

export function Button({ variant = "secondary", busy, children, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" | "ghost"; busy?: boolean }) {
  return <button className={`button button-${variant}`} disabled={busy || props.disabled} {...props}>{busy ? <span className="spinner" /> : null}{children}</button>;
}

export function Field({ label, hint, error, children, wide }: { label: string; hint?: string; error?: string; children: ReactNode; wide?: boolean }) {
  return <label className={`field ${wide ? "field-wide" : ""}`}><span className="field-label">{label}</span>{children}{hint ? <span className="field-hint">{hint}</span> : null}{error ? <span className="field-error">{error}</span> : null}</label>;
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) { return <input className="input" {...props} />; }
export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) { return <select className="select" {...props} />; }
export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) { return <textarea className="textarea" {...props} />; }

export function StatusPill({ value }: { value: string }) {
  const tone = value.includes("FAILED") || value.includes("ERROR") || value === "CRITICAL" ? "red"
    : value.includes("WAIT") || value === "HIGH" || value === "SUSPICIOUS" ? "amber"
      : value.includes("COMPLETE") || value.includes("SUCCEEDED") || value === "NO_FINDING" ? "green" : "blue";
  return <span className={`pill pill-${tone}`}>{value}</span>;
}

export function EmptyState({ icon = "◇", title, description, action }: { icon?: string; title: string; description: string; action?: ReactNode }) {
  return <div className="empty-state"><div className="empty-icon">{icon}</div><h3>{title}</h3><p>{description}</p>{action}</div>;
}

export function Modal({ title, children, onClose, size = "normal" }: { title: string; children: ReactNode; onClose?: () => void; size?: "normal" | "wide" }) {
  return <div className="modal-backdrop" role="dialog" aria-modal="true"><div className={`modal modal-${size}`}><header className="modal-header"><h2>{title}</h2>{onClose ? <button className="icon-button" onClick={onClose} aria-label="关闭">×</button> : null}</header><div className="modal-body">{children}</div></div></div>;
}

export function Section({ title, description, children, action }: { title: string; description?: string; children: ReactNode; action?: ReactNode }) {
  return <section className="settings-section"><div className="section-heading"><div><h3>{title}</h3>{description ? <p>{description}</p> : null}</div>{action}</div>{children}</section>;
}

export function formatTime(value: string | number): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "--" : date.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

export function shortId(value: string): string { return value.length > 20 ? `${value.slice(0, 12)}…${value.slice(-6)}` : value; }
