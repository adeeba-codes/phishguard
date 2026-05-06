import { useState, useEffect, useRef } from "react";

// ─── Types ────────────────────────────────────────────────────────────────────
interface AnalysisResult {
  label: "PHISHING" | "SAFE";
  confidence: number;
  red_flags: string[];
  explanation: string;
  virustotal_detections?: number | null;
}
interface HistoryItem {
  id: number;
  input: string;
  label: "PHISHING" | "SAFE";
  confidence: number;
  tab: "url" | "email";
  time: string;
}

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

const DEMO_URLS = [
  { label: "🎣 Phishing URL",    value: "http://paypa1-secure-login.xyz/verify?user=you@gmail.com" },
  { label: "✅ Safe URL",         value: "https://github.com/login" },
  { label: "⚠️ Suspicious URL",  value: "http://192.168.1.1/bankofamerica/login-confirm.php" },
];
const DEMO_EMAILS = [
  { label: "🎣 Phishing email", subject: "Urgent: Verify your account now",
    value: `Dear Customer,\n\nUnusual activity was detected on your account. Your account will be suspended within 24 hours unless you confirm your password and bank account details immediately.\n\nClick here to verify: http://paypa1-secure.tk/verify\n\nAct now — limited time.` },
  { label: "✅ Safe email", subject: "Your GitHub pull request was merged",
    value: `Hi there,\n\nYour pull request "Fix: navbar responsive layout" was successfully merged into main.\n\nView on GitHub: https://github.com/your-repo/pull/42\n\nThanks for contributing!` },
];

// ─── Animated confidence bar ──────────────────────────────────────────────────
function ConfBar({ value, isPhishing }: { value: number; isPhishing: boolean }) {
  const [w, setW] = useState(0);
  useEffect(() => { const t = setTimeout(() => setW(value * 100), 100); return () => clearTimeout(t); }, [value]);
  const color = isPhishing ? "var(--red)" : "var(--green)";
  return (
    <div>
      <div style={{ display:"flex", justifyContent:"space-between", fontSize:11, color:"var(--muted)", marginBottom:6, fontFamily:"var(--mono)", letterSpacing:1 }}>
        <span>CONFIDENCE</span>
        <span style={{ color, fontWeight:700 }}>{Math.round(value*100)}%</span>
      </div>
      <div style={{ height:4, background:"rgba(255,255,255,0.06)", borderRadius:99, overflow:"hidden" }}>
        <div style={{ height:"100%", borderRadius:99, background:`linear-gradient(90deg, ${color}88, ${color})`,
          width:`${w}%`, transition:"width 1s cubic-bezier(.4,0,.2,1)", boxShadow:`0 0 12px ${color}66` }} />
      </div>
    </div>
  );
}

// ─── Scanline overlay ─────────────────────────────────────────────────────────
function ScanOverlay() {
  return (
    <div style={{ position:"absolute", inset:0, pointerEvents:"none", overflow:"hidden", borderRadius:"inherit" }}>
      <div className="scanline" />
    </div>
  );
}

// ─── Result card ──────────────────────────────────────────────────────────────
function ResultCard({ result, input }: { result: AnalysisResult; input: string }) {
  const [flagsOpen, setFlagsOpen] = useState(true);
  const [copied, setCopied] = useState(false);
  const isPhishing = result.label === "PHISHING";
  const accent = isPhishing ? "var(--red)" : "var(--green)";

  function copy() {
    const t = `PHISHGUARD REPORT\n${"─".repeat(40)}\nVerdict: ${result.label}\nConfidence: ${Math.round(result.confidence*100)}%\n\nAnalysis:\n${result.explanation}\n\nRed Flags:\n${result.red_flags.map(f=>`• ${f}`).join("\n")}`;
    navigator.clipboard.writeText(t);
    setCopied(true); setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="result-card" style={{ "--accent": accent } as React.CSSProperties}>
      {/* Header bar */}
      <div style={{ display:"flex", alignItems:"center", gap:12, padding:"16px 20px",
        borderBottom:"1px solid var(--border)", background:"rgba(255,255,255,0.02)",
        flexWrap:"wrap" }}>
        <div style={{ width:36, height:36, borderRadius:10, flexShrink:0,
          display:"flex", alignItems:"center", justifyContent:"center",
          background:`color-mix(in srgb, var(--accent) 12%, transparent)`,
          color:"var(--accent)", fontSize:18 }}>
          {isPhishing ? "⚠" : "✓"}
        </div>
        <div style={{ flex:1 }}>
          <div style={{ fontSize:12, fontFamily:"var(--mono)", fontWeight:700, letterSpacing:2, color:accent }}>
            {isPhishing ? "PHISHING DETECTED" : "LOOKS SAFE"}
          </div>
          <div style={{ fontSize:11, color:"var(--muted)", marginTop:2 }}>
            {isPhishing ? "Do not proceed — this content is dangerous" : "No significant threats found"}
          </div>
        </div>
        {result.virustotal_detections != null && result.virustotal_detections > 0 && (
          <div style={{ background:"rgba(255,68,102,0.12)", color:"var(--red)", fontSize:11,
            fontFamily:"var(--mono)", padding:"4px 10px", borderRadius:99,
            border:"1px solid rgba(255,68,102,0.2)", whiteSpace:"nowrap" }}>
            🦠 {result.virustotal_detections} VT detections
          </div>
        )}
        <button onClick={copy} className="copy-btn">{copied ? "✓ Copied" : "Copy"}</button>
      </div>

      {/* Body */}
      <div style={{ padding:"16px 20px 20px" }}>
        <div style={{ marginBottom:18 }}>
          <ConfBar value={result.confidence} isPhishing={isPhishing} />
        </div>

        {/* AI explanation */}
        <div style={{ background:"rgba(255,255,255,0.03)", border:"1px solid var(--border)",
          borderRadius:10, padding:"14px 16px", marginBottom:14 }}>
          <div style={{ fontSize:10, fontFamily:"var(--mono)", letterSpacing:1.5,
            color:"var(--muted)", marginBottom:8 }}>◈ AI ANALYSIS</div>
          <p style={{ fontSize:13.5, color:"var(--text)", lineHeight:1.7, margin:0 }}>
            {result.explanation}
          </p>
        </div>

        {/* Red flags */}
        {result.red_flags.length > 0 && (
          <div>
            <button onClick={() => setFlagsOpen(v=>!v)} className="flags-toggle" style={{ color:accent }}>
              <span>{flagsOpen ? "▾" : "▸"}</span>
              &nbsp;{result.red_flags.length} RED FLAG{result.red_flags.length !== 1 ? "S" : ""} DETECTED
            </button>
            {flagsOpen && (
              <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
                {result.red_flags.map((f,i) => (
                  <div key={i} style={{ display:"flex", gap:8, alignItems:"flex-start",
                    padding:"8px 10px", background:"rgba(255,68,102,0.04)",
                    border:"1px solid rgba(255,68,102,0.1)", borderRadius:8 }}>
                    <span style={{ color:accent, flexShrink:0 }}>▸</span>
                    <span style={{ fontSize:13, color:"var(--text-dim)", lineHeight:1.5 }}>{f}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Input preview */}
        {isPhishing && input && (
          <div style={{ marginTop:12, padding:"10px 12px",
            background:"rgba(255,68,102,0.04)", border:"1px dashed rgba(255,68,102,0.2)", borderRadius:8 }}>
            <div style={{ fontSize:10, fontFamily:"var(--mono)", color:"var(--muted)", letterSpacing:1, marginBottom:6 }}>SCANNED INPUT</div>
            <div style={{ fontSize:12, fontFamily:"var(--mono)", color:"var(--red-dim)", wordBreak:"break-all", lineHeight:1.6 }}>
              {input.slice(0,180)}{input.length>180?"…":""}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Scanning state ───────────────────────────────────────────────────────────
function ScanningState() {
  const [dots, setDots] = useState(".");
  useEffect(() => {
    const t = setInterval(() => setDots(d => d.length >= 3 ? "." : d+"."), 400);
    return () => clearInterval(t);
  }, []);
  return (
    <div style={{ padding:"36px 0", textAlign:"center" }}>
      <div className="scan-ring" />
      <div style={{ marginTop:20, fontFamily:"var(--mono)", fontSize:12, color:"var(--muted)", letterSpacing:2 }}>
        SCANNING{dots}
      </div>
      <div style={{ fontSize:11, color:"var(--muted)", opacity:.4, marginTop:4 }}>
        Analyzing patterns across threat databases
      </div>
    </div>
  );
}

// ─── App ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [tab, setTab]       = useState<"url"|"email">("url");
  const [url, setUrl]       = useState("");
  const [emailText, setEmail] = useState("");
  const [subject, setSubject] = useState("");
  const [result, setResult] = useState<AnalysisResult|null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]   = useState("");
  const [history, setHistory] = useState<HistoryItem[]>(() => {
    try { return JSON.parse(localStorage.getItem("pg_hist")||"[]"); } catch { return []; }
  });
  const [stats, setStats] = useState({ total:0, phishing:0 });
  const inputRef = useRef<HTMLInputElement>(null);
  const currentInput = tab==="url" ? url : emailText;

  useEffect(() => {
    const s = JSON.parse(localStorage.getItem("pg_stats")||'{"total":0,"phishing":0}');
    setStats(s);
  }, []);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey||e.ctrlKey) && e.key==="Enter") analyze();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [url, emailText, tab]);

  async function analyze() {
    setError(""); setResult(null);
    if (!currentInput.trim()) { setError("Enter a URL or email to scan."); return; }
    setLoading(true);
    try {
      const endpoint = tab==="url" ? "/analyze-url" : "/analyze-email";
      const body = tab==="url"
        ? JSON.stringify({ url: url.trim() })
        : JSON.stringify({ email_text: emailText.trim(), subject: subject.trim() });
      const resp = await fetch(`${API_BASE}${endpoint}`, {
        method:"POST", headers:{"Content-Type":"application/json"}, body
      });
      if (!resp.ok) { const e = await resp.json(); throw new Error(e.detail||"Server error"); }
      const data: AnalysisResult = await resp.json();
      setResult(data);

      const item: HistoryItem = {
        id: Date.now(),
        input: currentInput.slice(0,55)+(currentInput.length>55?"…":""),
        label: data.label, confidence: data.confidence, tab,
        time: new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"}),
      };
      const updated = [item, ...history].slice(0, 6);
      setHistory(updated);
      localStorage.setItem("pg_hist", JSON.stringify(updated));

      const newStats = { total:stats.total+1, phishing:stats.phishing+(data.label==="PHISHING"?1:0) };
      setStats(newStats);
      localStorage.setItem("pg_stats", JSON.stringify(newStats));
    } catch(e: unknown) {
      setError(e instanceof Error ? e.message : "Something went wrong.");
    } finally { setLoading(false); }
  }

  function loadDemo(type:"url"|"email", i:number) {
    setTab(type); setResult(null); setError("");
    if (type==="url") setUrl(DEMO_URLS[i].value);
    else { setEmail(DEMO_EMAILS[i].value); setSubject(DEMO_EMAILS[i].subject); }
  }

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500;700&display=swap');

        :root {
          --bg:       #080d17;
          --surface:  #0d1526;
          --surface2: #111d33;
          --border:   rgba(255,255,255,0.07);
          --border2:  rgba(255,255,255,0.12);
          --text:     #e2e8f0;
          --text-dim: #94a3b8;
          --muted:    #475569;
          --green:    #00e5a0;
          --red:      #ff4466;
          --red-dim:  #ff6b88;
          --mono:     'JetBrains Mono', monospace;
          --display:  'Syne', sans-serif;
          --body:     'DM Sans', sans-serif;
        }
        *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
        body {
          background: var(--bg); color: var(--text); font-family: var(--body);
          min-height: 100vh;
          background-image:
            radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0,229,160,0.07) 0%, transparent 60%),
            radial-gradient(ellipse 50% 40% at 90% 90%, rgba(79,158,255,0.04) 0%, transparent 50%);
        }
        ::-webkit-scrollbar { width:4px; }
        ::-webkit-scrollbar-thumb { background:var(--border2); border-radius:99px; }

        .scanline {
          position:absolute; left:0; right:0; height:2px;
          background: linear-gradient(90deg, transparent, rgba(0,229,160,0.25), transparent);
          animation: scan 3s linear infinite;
        }
        @keyframes scan { from{top:-2px} to{top:100%} }

        .scan-ring {
          width:52px; height:52px; border-radius:50%;
          border:2px solid transparent;
          border-top-color: var(--green);
          border-right-color: rgba(0,229,160,0.25);
          animation: spin .75s linear infinite;
          margin: 0 auto;
          box-shadow: 0 0 20px rgba(0,229,160,0.15);
        }
        @keyframes spin { to{transform:rotate(360deg)} }

        .result-card {
          border:1px solid var(--border);
          border-top:2px solid var(--accent, var(--green));
          border-radius:16px; overflow:hidden;
          background: var(--surface);
          animation: slideUp .3s cubic-bezier(.4,0,.2,1);
          box-shadow: 0 20px 60px rgba(0,0,0,0.5);
        }
        @keyframes slideUp { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:none} }

        .copy-btn {
          background:transparent; border:1px solid var(--border2);
          color:var(--muted); font-size:11px; font-family:var(--mono);
          padding:4px 12px; border-radius:6px; cursor:pointer;
          transition:all .15s; letter-spacing:.5px; margin-left:auto;
        }
        .copy-btn:hover { color:var(--text); background:rgba(255,255,255,0.04); }

        .flags-toggle {
          display:flex; align-items:center; gap:5px;
          background:none; border:none; cursor:pointer;
          font-size:11px; font-family:var(--mono); font-weight:700;
          letter-spacing:1.5px; padding:0; margin-bottom:8px;
          transition:opacity .15s;
        }
        .flags-toggle:hover { opacity:.7; }

        .main-input {
          width:100%; background:var(--surface2);
          border:1px solid var(--border); border-radius:10px;
          padding:12px 16px; color:var(--text);
          font-family:var(--mono); font-size:13px;
          outline:none; transition:border-color .15s, box-shadow .15s;
          resize:vertical;
        }
        .main-input::placeholder { color:var(--muted); }
        .main-input:focus {
          border-color:rgba(0,229,160,0.4);
          box-shadow:0 0 0 3px rgba(0,229,160,0.06);
        }

        .tab-btn {
          flex:1; padding:9px 12px; border-radius:8px; border:none; cursor:pointer;
          font-size:13px; font-weight:500; font-family:var(--body);
          transition:all .15s;
        }
        .tab-btn.active   { background:rgba(0,229,160,0.1); color:var(--green); box-shadow:inset 0 0 0 1px rgba(0,229,160,0.25); }
        .tab-btn.inactive { background:transparent; color:var(--muted); }
        .tab-btn.inactive:hover { background:rgba(255,255,255,0.03); color:var(--text-dim); }

        .analyze-btn {
          width:100%; padding:14px; border:none; border-radius:10px;
          font-size:14px; font-weight:600; cursor:pointer; font-family:var(--body);
          background: linear-gradient(135deg, #00e5a0, #00b87a);
          color:#001a0f; transition:all .15s; letter-spacing:.3px;
        }
        .analyze-btn:hover:not(:disabled) { transform:translateY(-1px); box-shadow:0 8px 24px rgba(0,229,160,0.3); }
        .analyze-btn:active:not(:disabled) { transform:translateY(0); }
        .analyze-btn:disabled { background:rgba(0,229,160,0.12); color:rgba(0,229,160,0.35); cursor:not-allowed; }

        .chip {
          padding:5px 12px; border-radius:99px; border:1px solid var(--border);
          background:transparent; font-size:12px; cursor:pointer;
          color:var(--text-dim); font-family:var(--body); transition:all .15s; white-space:nowrap;
        }
        .chip:hover { border-color:rgba(0,229,160,0.3); color:var(--green); background:rgba(0,229,160,0.05); }

        .hist-item {
          display:flex; align-items:center; gap:10px;
          padding:9px 14px; border-radius:10px;
          border:1px solid var(--border); background:var(--surface);
          transition:border-color .15s;
        }
        .hist-item:hover { border-color:var(--border2); }
      `}</style>

      <div style={{ maxWidth:620, margin:"0 auto", padding:"44px 16px 64px", position:"relative", zIndex:1 }}>

        {/* Header */}
        <div style={{ textAlign:"center", marginBottom:36 }}>
          <div style={{ display:"inline-flex", alignItems:"center", gap:8, marginBottom:14,
            background:"rgba(0,229,160,0.06)", border:"1px solid rgba(0,229,160,0.15)",
            padding:"5px 16px", borderRadius:99, fontSize:10, fontFamily:"var(--mono)",
            color:"var(--green)", letterSpacing:2.5 }}>
            ◈ AI PHISHING DETECTOR
          </div>
          <h1 style={{ fontFamily:"var(--display)", fontSize:50, fontWeight:800,
            color:"var(--text)", lineHeight:1, letterSpacing:-2, marginBottom:12 }}>
            Phish<span style={{ color:"var(--green)" }}>Guard</span>
          </h1>
          <p style={{ color:"var(--muted)", fontSize:14, lineHeight:1.65, maxWidth:380, margin:"0 auto" }}>
            Real-time phishing detection for URLs &amp; emails — powered by fine-tuned BERT + Gemini AI
          </p>

          {stats.total > 0 && (
            <div style={{ display:"inline-flex", gap:20, marginTop:18, padding:"8px 22px",
              background:"var(--surface)", border:"1px solid var(--border)", borderRadius:99,
              fontSize:12, fontFamily:"var(--mono)" }}>
              <span style={{ color:"var(--muted)" }}>SCANNED&nbsp;<span style={{ color:"var(--text)", fontWeight:700 }}>{stats.total}</span></span>
              <span style={{ color:"var(--border2)" }}>|</span>
              <span style={{ color:"var(--muted)" }}>THREATS&nbsp;<span style={{ color:"var(--red)", fontWeight:700 }}>{stats.phishing}</span></span>
              <span style={{ color:"var(--border2)" }}>|</span>
              <span style={{ color:"var(--muted)" }}>SAFE&nbsp;<span style={{ color:"var(--green)", fontWeight:700 }}>{stats.total-stats.phishing}</span></span>
            </div>
          )}
        </div>

        {/* Main card */}
        <div style={{ background:"var(--surface)", border:"1px solid var(--border)",
          borderRadius:20, padding:"24px", marginBottom:16, position:"relative", overflow:"hidden",
          boxShadow:"0 24px 60px rgba(0,0,0,0.5)" }}>
          <ScanOverlay />

          {/* Tabs */}
          <div style={{ display:"flex", gap:4, background:"rgba(255,255,255,0.03)",
            borderRadius:10, padding:4, marginBottom:20, border:"1px solid var(--border)" }}>
            {(["url","email"] as const).map(t => (
              <button key={t} className={`tab-btn ${tab===t?"active":"inactive"}`}
                onClick={() => { setTab(t); setResult(null); setError(""); }}>
                {t==="url" ? "🔗  Check URL" : "✉️  Check Email"}
              </button>
            ))}
          </div>

          {tab==="url" && (
            <input ref={inputRef} className="main-input" style={{ marginBottom:12 }}
              placeholder="Paste a URL — e.g. https://paypa1-secure.xyz/verify..."
              value={url} onChange={e=>setUrl(e.target.value)}
              onKeyDown={e=>e.key==="Enter"&&analyze()} />
          )}

          {tab==="email" && (
            <div style={{ display:"flex", flexDirection:"column", gap:8, marginBottom:12 }}>
              <input className="main-input" placeholder="Subject line (optional)"
                value={subject} onChange={e=>setSubject(e.target.value)} />
              <textarea className="main-input" rows={5}
                placeholder="Paste the email body here…"
                value={emailText} onChange={e=>setEmail(e.target.value)} />
            </div>
          )}

          {/* Demo chips */}
          <div style={{ display:"flex", flexWrap:"wrap", gap:6, marginBottom:16, alignItems:"center" }}>
            <span style={{ fontSize:10, color:"var(--muted)", fontFamily:"var(--mono)", letterSpacing:1.5 }}>TRY</span>
            {(tab==="url" ? DEMO_URLS : DEMO_EMAILS).map((d,i) => (
              <button key={i} className="chip" onClick={()=>loadDemo(tab,i)}>{d.label}</button>
            ))}
          </div>

          {error && (
            <div style={{ background:"rgba(255,68,102,0.08)", border:"1px solid rgba(255,68,102,0.25)",
              borderRadius:8, padding:"10px 14px", fontSize:13, color:"var(--red-dim)", marginBottom:12 }}>
              ⚠ {error}
            </div>
          )}

          <button className="analyze-btn" onClick={analyze} disabled={loading}>
            {loading ? "Scanning…" : "Analyze →"}
          </button>

          <div style={{ textAlign:"center", marginTop:8, fontSize:10, fontFamily:"var(--mono)",
            color:"var(--muted)", letterSpacing:.5 }}>
            ⌘ + Enter to analyze
          </div>
        </div>

        {/* Result */}
        {loading && <ScanningState />}
        {result && !loading && <ResultCard result={result} input={currentInput} />}

        {/* History */}
        {history.length > 0 && (
          <div style={{ marginTop:24 }}>
            <div style={{ fontSize:10, fontFamily:"var(--mono)", color:"var(--muted)",
              letterSpacing:2, marginBottom:10 }}>RECENT SCANS</div>
            <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
              {history.map(h => (
                <div key={h.id} className="hist-item">
                  <span style={{ fontSize:14 }}>{h.label==="PHISHING"?"🚨":"✅"}</span>
                  <span style={{ fontSize:10, color:"var(--muted)", fontFamily:"var(--mono)",
                    flexShrink:0, letterSpacing:.5 }}>
                    {h.tab.toUpperCase()}
                  </span>
                  <span style={{ fontSize:12, color:"var(--text-dim)", flex:1,
                    overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap",
                    fontFamily:"var(--mono)" }}>{h.input}</span>
                  <span style={{ fontSize:12, fontFamily:"var(--mono)", fontWeight:700, flexShrink:0,
                    color:h.label==="PHISHING"?"var(--red)":"var(--green)" }}>
                    {Math.round(h.confidence*100)}%
                  </span>
                  <span style={{ fontSize:11, color:"var(--muted)", flexShrink:0 }}>{h.time}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div style={{ textAlign:"center", marginTop:44, fontSize:10,
          fontFamily:"var(--mono)", color:"var(--muted)", letterSpacing:1.5 }}>
          PHISHGUARD · FASTAPI + BERT + GEMINI FLASH · MIT LICENSE
        </div>
      </div>
    </>
  );
}