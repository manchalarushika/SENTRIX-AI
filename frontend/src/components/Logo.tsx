export function LogoMark({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-label="SENTRIX AI">
      <defs>
        <linearGradient id="sx-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#22d3ee" />
          <stop offset="1" stopColor="#6366f1" />
        </linearGradient>
      </defs>
      <path d="M32 3 56 12v18c0 15-10 26-24 31C18 56 8 45 8 30V12z" fill="none" stroke="url(#sx-g)" strokeWidth="4" />
      <circle cx="32" cy="22" r="4" fill="#22d3ee" />
      <circle cx="22" cy="38" r="4" fill="#6366f1" />
      <circle cx="42" cy="38" r="4" fill="#6366f1" />
      <path d="M32 22 22 38h20z" fill="none" stroke="#94a3b8" strokeWidth="2" />
    </svg>
  );
}

export function Logo({ collapsed }: { collapsed?: boolean }) {
  return (
    <div className="logo">
      <LogoMark />
      {!collapsed && (
        <div>
          <div className="logo-title">SENTRIX <span>AI</span></div>
          <div className="logo-sub">Autonomous Cyber Defense</div>
        </div>
      )}
    </div>
  );
}
