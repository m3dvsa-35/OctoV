import clsx from "clsx";
import type { LucideIcon } from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { Severity } from "../api/types";

export function Button({
  icon: Icon,
  children,
  variant = "ghost",
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  icon?: LucideIcon;
  variant?: "ghost" | "primary" | "outline";
}) {
  return (
    <button
      type="button"
      className={clsx(
        "inline-flex h-7 cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-md px-2.5 text-[12.5px] font-medium transition-colors duration-150 disabled:cursor-default disabled:opacity-40",
        variant === "primary" && "bg-accent text-accent-fg hover:brightness-110",
        variant === "ghost" && "text-muted hover:bg-raised hover:text-fg",
        variant === "outline" && "border border-line text-fg hover:bg-raised",
        className,
      )}
      {...rest}
    >
      {Icon && <Icon size={15} strokeWidth={1.75} aria-hidden />}
      {children}
    </button>
  );
}

export function IconButton({
  icon: Icon,
  label,
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { icon: LucideIcon; label: string }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={clsx(
        "inline-flex size-7 cursor-pointer items-center justify-center rounded-md text-muted transition-colors duration-150 hover:bg-raised hover:text-fg disabled:cursor-default disabled:opacity-35",
        className,
      )}
      {...rest}
    >
      <Icon size={16} strokeWidth={1.75} aria-hidden />
    </button>
  );
}

const SEVERITY_STYLE: Record<Severity, string> = {
  high: "text-sev-high bg-sev-high/12 ring-sev-high/30",
  medium: "text-sev-medium bg-sev-medium/12 ring-sev-medium/30",
  low: "text-sev-low bg-sev-low/12 ring-sev-low/30",
  info: "text-sev-info bg-sev-info/12 ring-sev-info/30",
};

/** Severity is always spelled out; colour is a secondary cue. */
export function SeverityBadge({ severity, label }: { severity: Severity; label: string }) {
  return (
    <span
      className={clsx(
        "inline-flex h-5 items-center gap-1 rounded px-1.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset",
        SEVERITY_STYLE[severity],
      )}
    >
      <span className="size-1.5 rounded-full bg-current" aria-hidden />
      {label}
    </span>
  );
}

export function Tabs<T extends string>({
  value,
  onChange,
  items,
  right,
}: {
  value: T;
  onChange: (v: T) => void;
  items: { id: T; label: string; icon?: LucideIcon; badge?: number | string }[];
  right?: ReactNode;
}) {
  return (
    <div className="flex h-9 shrink-0 items-center gap-0.5 border-b border-line px-1.5" role="tablist">
      {items.map(({ id, label, icon: Icon, badge }) => (
        <button
          key={id}
          type="button"
          role="tab"
          aria-selected={value === id}
          onClick={() => onChange(id)}
          className={clsx(
            "relative inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-md px-2.5 text-[12.5px] transition-colors duration-150",
            value === id
              ? "bg-raised text-fg shadow-[inset_0_-2px_0_var(--accent)]"
              : "text-muted hover:text-fg",
          )}
        >
          {Icon && <Icon size={14} strokeWidth={1.75} aria-hidden />}
          {label}
          {badge !== undefined && (
            <span className="rounded bg-bg px-1 font-mono text-[10.5px] text-muted">{badge}</span>
          )}
        </button>
      ))}
      <div className="ml-auto flex items-center gap-1">{right}</div>
    </div>
  );
}

export function Empty({ icon: Icon, title, body, children }: {
  icon: LucideIcon;
  title: string;
  body?: string;
  children?: ReactNode;
}) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 p-8 text-center">
      <div className="rounded-xl bg-raised p-3 text-muted">
        <Icon size={22} strokeWidth={1.5} aria-hidden />
      </div>
      <div className="text-[13.5px] font-medium">{title}</div>
      {body && <p className="max-w-sm text-[12.5px] leading-relaxed text-muted">{body}</p>}
      {children}
    </div>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="rounded border border-line bg-bg px-1 font-mono text-[10.5px] text-muted">
      {children}
    </kbd>
  );
}

/** Two-or-more option switch where the active choice is always visible. */
export function Segmented<T extends string>({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: T;
  onChange: (v: T) => void;
  options: { id: T; label: string; icon?: LucideIcon }[];
}) {
  return (
    <div role="radiogroup" aria-label={label} title={label} className="flex h-7 items-center rounded-md border border-line bg-bg p-0.5">
      {options.map(({ id, label: text, icon: Icon }) => (
        <button
          key={id}
          type="button"
          role="radio"
          aria-checked={value === id}
          onClick={() => value !== id && onChange(id)}
          className={clsx(
            "inline-flex h-full cursor-pointer items-center gap-1 whitespace-nowrap rounded px-2 text-[11.5px] font-medium transition-colors duration-150",
            value === id ? "bg-raised text-fg shadow-sm" : "text-muted hover:text-fg",
          )}
        >
          {Icon && <Icon size={13} strokeWidth={1.9} aria-hidden />}
          {text}
        </button>
      ))}
    </div>
  );
}
