import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase, edgeUrl } from '@/lib/supabase';
import { Card, SectionTitle, Button, Input, Label, Badge } from '@/components/ui';
import { LinkScan, LinkVerdict, RiskIndicator, VERDICT_STYLES, SEVERITY_STYLES } from '@/lib/types';
import { Route } from '@/components/AppShell';
import {
  Link2, MessageSquare, QrCode, KeyRound, ShieldCheck, ShieldAlert,
  Copy, RefreshCw, CheckCircle2, AlertTriangle, Eye, EyeOff, Zap,
  History, ChevronRight, Info, Loader2, ScanLine, Lightbulb, X,
} from 'lucide-react';

type Tab = 'url' | 'message' | 'qr' | 'password';

export function Tools({ onNavigate }: { onNavigate: (r: Route) => void }) {
  const [tab, setTab] = useState<Tab>('url');

  const tabs: { id: Tab; label: string; icon: typeof Link2; desc: string }[] = [
    { id: 'url',      label: 'Link Scanner',       icon: Link2,         desc: 'Check suspicious URLs' },
    { id: 'message',  label: 'Scam Message',       icon: MessageSquare, desc: 'Analyze messages for scams' },
    { id: 'qr',       label: 'QR Scanner',         icon: QrCode,        desc: 'Decode & check QR codes' },
    { id: 'password', label: 'Password Tools',     icon: KeyRound,      desc: 'Strength check & generator' },
  ];

  return (
    <div className="space-y-6 fade-up">
      <div>
        <h1 className="text-2xl lg:text-3xl font-semibold tracking-tight text-slate-100 flex items-center gap-2.5">
          <ShieldCheck size={26} className="text-cyan-300" /> Security Tools
        </h1>
        <p className="text-slate-400 mt-1 text-sm">Check suspicious links, analyze scam messages, scan QR codes, and manage passwords — all in one place.</p>
      </div>

      {/* Tab selector */}
      <div className="flex flex-wrap gap-1.5">
        {tabs.map((t) => {
          const Icon = t.icon;
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition ${
                active
                  ? 'bg-cyan-400/10 text-cyan-200 border border-cyan-400/30'
                  : 'bg-veil-800/60 text-slate-400 hover:text-slate-200 border border-transparent'
              }`}
            >
              <Icon size={15} /> {t.label}
            </button>
          );
        })}
      </div>

      {tab === 'url'      && <UrlScanner onNavigate={onNavigate} />}
      {tab === 'message'  && <MessageAnalyzer />}
      {tab === 'qr'       && <QrScanner />}
      {tab === 'password' && <PasswordTools />}
    </div>
  );
}

// ==================== URL SCANNER ====================
function UrlScanner({ onNavigate }: { onNavigate: (r: Route) => void }) {
  const { session } = useAuth();
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LinkScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<LinkScan[]>([]);
  const [showHistory, setShowHistory] = useState(false);

  async function loadHistory() {
    const { data } = await supabase
      .from('link_scans')
      .select('*')
      .eq('scan_type', 'url')
      .order('created_at', { ascending: false })
      .limit(10);
    setHistory((data as LinkScan[]) ?? []);
  }

  useEffect(() => { loadHistory(); }, []);

  async function scan() {
    if (!input.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const resp = await fetch(edgeUrl('link-scanner'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session?.access_token}`,
        },
        body: JSON.stringify({ input, scan_type: 'url' }),
      });
      const data = await resp.json().catch(() => null);
      if (!resp.ok) {
        setError(data?.error ?? `Scan failed (${resp.status})`);
        setLoading(false);
        return;
      }
      setResult(data as LinkScanResult);
      await loadHistory();
    } catch {
      setError('Could not reach the scanner. Please try again.');
    }
    setLoading(false);
  }

  return (
    <div className="space-y-5">
      <Card className="p-5">
        <SectionTitle
          title="Suspicious Link Scanner"
          subtitle="Check any URL for phishing, redirects, and known risk indicators"
          icon={<Link2 size={18} />}
        />
        <div className="space-y-3">
          <div>
            <Label>URL to check</Label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Link2 size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <Input
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && scan()}
                  placeholder="https://suspicious-site.com or example.com"
                  className="pl-9"
                />
              </div>
              <Button onClick={scan} loading={loading} disabled={!input.trim()}>
                <ScanLine size={15} /> Scan
              </Button>
            </div>
          </div>
          <p className="text-[11px] text-slate-500">
            The scanner does not visit dangerous URLs in your browser. It uses server-side checks with SSRF protection, redirect analysis, and phishing heuristics. No tool can guarantee a URL is safe.
          </p>
          {error && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">{error}</div>
          )}
        </div>
      </Card>

      {loading && (
        <Card className="p-8 flex items-center justify-center gap-3 text-slate-400">
          <Loader2 size={20} className="animate-spin text-cyan-300" /> Analyzing URL…
        </Card>
      )}

      {result && <ScanResultCard result={result} />}

      {/* Scan history */}
      <Card className="p-5">
        <button
          onClick={() => setShowHistory(!showHistory)}
          className="w-full flex items-center justify-between text-left"
        >
          <div className="flex items-center gap-2 text-sm font-medium text-slate-200">
            <History size={16} className="text-slate-500" /> Recent scans
            <Badge tone="slate">{history.length}</Badge>
          </div>
          <ChevronRight size={16} className={`text-slate-500 transition ${showHistory ? 'rotate-90' : ''}`} />
        </button>
        {showHistory && (
          <div className="mt-4 space-y-2">
            {history.length === 0 ? (
              <p className="text-sm text-slate-500">No scans yet. Run a scan to see your history here.</p>
            ) : (
              history.map((scan) => (
                <button
                  key={scan.id}
                  onClick={() => onNavigate('tools')}
                  className="w-full flex items-center gap-3 rounded-lg p-2.5 text-left hover:bg-veil-800/40 transition border border-slate-800/60"
                >
                  <div className={`w-2 h-2 rounded-full shrink-0 ${VERDICT_STYLES[scan.verdict].dot}`} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-slate-200 truncate">{scan.target_host ?? scan.input}</div>
                    <div className="text-[11px] text-slate-500 font-mono-tight">
                      {VERDICT_STYLES[scan.verdict].label} · {new Date(scan.created_at).toLocaleDateString()}
                    </div>
                  </div>
                  <span className="text-xs text-slate-500 font-mono-tight">{scan.risk_score}/100</span>
                </button>
              ))
            )}
          </div>
        )}
      </Card>
    </div>
  );
}

interface LinkScanResult {
  verdict: LinkVerdict;
  risk_score: number;
  indicators: RiskIndicator[];
  recommendations: string[];
  target_url: string | null;
  target_host: string | null;
  details: Record<string, unknown>;
}

function ScanResultCard({ result }: { result: LinkScanResult }) {
  const style = VERDICT_STYLES[result.verdict];
  return (
    <Card className={`p-5 border ${style.border} ${style.bg}`}>
      <div className="flex items-start gap-4">
        <div className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 ${style.bg} ${style.border} border`}>
          {result.verdict === 'high_risk' ? <ShieldAlert size={24} className="text-rose-300" /> :
           result.verdict === 'suspicious' ? <AlertTriangle size={24} className="text-amber-300" /> :
           result.verdict === 'low_risk' ? <CheckCircle2 size={24} className="text-emerald-300" /> :
           <Info size={24} className="text-slate-300" />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className={`text-lg font-semibold ${style.text}`}>{style.label}</h3>
            <Badge tone="slate">{result.risk_score}/100</Badge>
          </div>
          {result.target_host && (
            <p className="text-sm text-slate-400 mt-0.5 truncate">
              Target: <span className="text-slate-300 font-mono-tight">{result.target_host}</span>
            </p>
          )}
        </div>
      </div>

      {result.indicators.length > 0 && (
        <div className="mt-5 space-y-2.5">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Risk indicators ({result.indicators.length})</div>
          {result.indicators.map((ind) => {
            const s = SEVERITY_STYLES[ind.severity];
            return (
              <div key={ind.id} className={`rounded-lg border ${s.border} ${s.bg} p-3`}>
                <div className="flex items-center gap-2">
                  <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
                  <span className={`text-sm font-medium ${s.text}`}>{ind.label}</span>
                  <Badge tone="slate">{ind.severity}</Badge>
                </div>
                <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">{ind.detail}</p>
              </div>
            );
          })}
        </div>
      )}

      {result.indicators.length === 0 && result.verdict === 'low_risk' && (
        <div className="mt-4 rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3.5">
          <div className="flex items-start gap-2.5">
            <CheckCircle2 size={15} className="text-emerald-300 mt-0.5 shrink-0" />
            <p className="text-xs text-slate-300 leading-relaxed">
              No significant risk indicators were detected. This does not guarantee the site is safe — always verify you are on the correct site before entering sensitive information.
            </p>
          </div>
        </div>
      )}

      {result.recommendations.length > 0 && (
        <div className="mt-5">
          <div className="text-[10px] uppercase tracking-wider text-cyan-400 mb-2">Recommended next steps</div>
          <ol className="space-y-2">
            {result.recommendations.map((rec, i) => (
              <li key={i} className="flex gap-2.5 text-sm text-slate-300">
                <span className="w-5 h-5 rounded-full bg-cyan-500/15 text-cyan-300 text-[11px] font-mono-tight flex items-center justify-center shrink-0 mt-0.5">{i + 1}</span>
                <span className="leading-relaxed">{rec}</span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </Card>
  );
}

// ==================== MESSAGE ANALYZER ====================
function MessageAnalyzer() {
  const { session } = useAuth();
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LinkScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function analyze() {
    if (!input.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const resp = await fetch(edgeUrl('link-scanner'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session?.access_token}`,
        },
        body: JSON.stringify({ input, scan_type: 'message' }),
      });
      const data = await resp.json().catch(() => null);
      if (!resp.ok) {
        setError(data?.error ?? `Analysis failed (${resp.status})`);
        setLoading(false);
        return;
      }
      setResult(data as LinkScanResult);
    } catch {
      setError('Could not reach the analyzer. Please try again.');
    }
    setLoading(false);
  }

  return (
    <div className="space-y-5">
      <Card className="p-5">
        <SectionTitle
          title="Scam Message Analyzer"
          subtitle="Paste a suspicious email, SMS, or chat message to check for scam indicators"
          icon={<MessageSquare size={18} />}
        />
        <div className="space-y-3">
          <div>
            <Label>Message to analyze</Label>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Paste the full message here — including sender, subject, and body…"
              rows={7}
              className="w-full rounded-lg border border-slate-700/80 bg-veil-950/60 px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/20 outline-none transition resize-y"
            />
            <div className="flex items-center justify-between mt-2">
              <p className="text-[11px] text-slate-500">
                We check for urgency tactics, credential requests, fake prizes, embedded links, and phishing patterns. Your message is not stored — only the scan result.
              </p>
              <Button onClick={analyze} loading={loading} disabled={!input.trim()} size="sm">
                <ScanLine size={15} /> Analyze
              </Button>
            </div>
          </div>
          {error && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">{error}</div>
          )}
        </div>
      </Card>

      {loading && (
        <Card className="p-8 flex items-center justify-center gap-3 text-slate-400">
          <Loader2 size={20} className="animate-spin text-cyan-300" /> Analyzing message…
        </Card>
      )}

      {result && <ScanResultCard result={result} />}

      <Card className="p-5 border-cyan-500/20 bg-cyan-500/5">
        <div className="flex items-start gap-3">
          <Lightbulb size={18} className="text-cyan-300 mt-0.5 shrink-0" />
          <div className="text-sm text-slate-300">
            <p className="font-medium text-cyan-200">How to spot a scam yourself</p>
            <ul className="mt-2 space-y-1.5 text-xs text-slate-400">
              <li>• <span className="text-slate-300">Urgency:</span> "Act now or your account will be closed" — legitimate services give you time.</li>
              <li>• <span className="text-slate-300">Credentials:</span> No real organization asks for your password, OTP, or gift cards.</li>
              <li>• <span className="text-slate-300">Sender mismatch:</span> The email says "Bank of America" but the domain is bofa-secure-verify.xyz.</li>
              <li>• <span className="text-slate-300">Too good to be true:</span> Lottery wins, inheritances, and prizes you didn't enter for.</li>
              <li>• <span className="text-slate-300">Generic greetings:</span> "Dear Customer" instead of your name.</li>
            </ul>
          </div>
        </div>
      </Card>
    </div>
  );
}

// ==================== QR SCANNER ====================
function QrScanner() {
  const { session } = useAuth();
  const [scanning, setScanning] = useState(false);
  const [decodedUrl, setDecodedUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<LinkScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);

  const stopCamera = useCallback(() => {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
    setScanning(false);
  }, []);

  async function startCamera() {
    setError(null);
    setDecodedUrl(null);
    setScanResult(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' },
      });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.play();
      }
      setScanning(true);
      detectQr();
    } catch {
      setError('Could not access your camera. Allow camera access in your browser, or paste a URL manually below.');
    }
  }

  async function detectQr() {
    if (!videoRef.current || !scanning) return;
    // Check if BarcodeDetector is available (Chrome/Edge on Android)
    if ('BarcodeDetector' in window) {
      try {
        // @ts-expect-error - BarcodeDetector is not in TS types
        const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
        const detect = async () => {
          if (!scanning || !videoRef.current) return;
          try {
            const codes = await detector.detect(videoRef.current);
            if (codes && codes.length > 0) {
              const text = codes[0].rawValue;
              if (text) {
                handleDecoded(text);
                return;
              }
            }
          } catch { /* continue scanning */ }
          if (scanning) requestAnimationFrame(detect);
        };
        detect();
        return;
      } catch {
        // fall through to manual
      }
    }
    // No native BarcodeDetector — prompt user to use the URL scanner
    setError('Your browser does not support QR scanning via camera. You can paste the URL from the QR code manually below.');
    stopCamera();
  }

  function handleDecoded(text: string) {
    stopCamera();
    setDecodedUrl(text);
    // Auto-scan the decoded URL
    if (text.startsWith('http://') || text.startsWith('https://')) {
      scanDecodedUrl(text);
    }
  }

  async function scanDecodedUrl(url: string) {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(edgeUrl('link-scanner'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session?.access_token}`,
        },
        body: JSON.stringify({ input: url, scan_type: 'qr' }),
      });
      const data = await resp.json().catch(() => null);
      if (!resp.ok) {
        setError(data?.error ?? `Scan failed (${resp.status})`);
        setLoading(false);
        return;
      }
      setScanResult(data as LinkScanResult);
    } catch {
      setError('Could not reach the scanner. Please try again.');
    }
    setLoading(false);
  }

  useEffect(() => {
    return () => stopCamera();
  }, [stopCamera]);

  return (
    <div className="space-y-5">
      <Card className="p-5">
        <SectionTitle
          title="QR Code Scanner"
          subtitle="Scan a QR code to see where it leads before you open it"
          icon={<QrCode size={18} />}
        />

        {/* Camera viewport */}
        {scanning && (
          <div className="relative rounded-xl overflow-hidden border border-slate-700 bg-black aspect-video max-w-md mx-auto">
            <video ref={videoRef} className="w-full h-full object-cover" playsInline muted />
            <div className="absolute inset-0 pointer-events-none">
              <div className="absolute inset-x-8 top-1/2 -translate-y-1/2 h-32 border-2 border-cyan-400/60 rounded-lg" />
              <div className="absolute inset-x-8 top-1/2 -translate-y-1/2 h-0.5 bg-cyan-400 scanline" />
            </div>
            <button
              onClick={stopCamera}
              className="absolute top-2 right-2 w-8 h-8 rounded-lg bg-black/60 text-white flex items-center justify-center hover:bg-black/80"
            >
              <X size={16} />
            </button>
          </div>
        )}

        {!scanning && !decodedUrl && (
          <div className="text-center py-6">
            <QrCode size={48} className="text-slate-600 mx-auto mb-3" />
            <Button onClick={startCamera}>
              <ScanLine size={16} /> Start camera scan
            </Button>
          </div>
        )}

        {error && (
          <div className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">{error}</div>
        )}

        {/* Decoded URL display */}
        {decodedUrl && (
          <div className="mt-4 rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-4">
            <div className="text-[10px] uppercase tracking-wider text-cyan-400 mb-1">QR code contains</div>
            <div className="text-sm text-slate-200 font-mono-tight break-all">{decodedUrl}</div>
            {!decodedUrl.startsWith('http') && (
              <p className="text-xs text-slate-400 mt-2">This QR code does not contain a URL. It may contain text, contact info, or Wi-Fi credentials. Do not follow any instructions in it without verifying the source.</p>
            )}
            {decodedUrl.startsWith('http') && !scanResult && !loading && (
              <Button size="sm" className="mt-3" onClick={() => scanDecodedUrl(decodedUrl)}>
                <ShieldCheck size={14} /> Check this URL
              </Button>
            )}
          </div>
        )}

        {/* Manual fallback */}
        {!scanning && (
          <div className="mt-4 pt-4 border-t border-slate-800/60">
            <Label>No camera? Paste the URL manually</Label>
            <ManualQrInput onScan={scanDecodedUrl} loading={loading} />
          </div>
        )}
      </Card>

      {loading && (
        <Card className="p-8 flex items-center justify-center gap-3 text-slate-400">
          <Loader2 size={20} className="animate-spin text-cyan-300" /> Checking decoded URL…
        </Card>
      )}

      {scanResult && <ScanResultCard result={scanResult} />}

      <Card className="p-4 border-amber-500/20 bg-amber-500/5">
        <div className="flex items-start gap-3">
          <Info size={16} className="text-amber-300 mt-0.5 shrink-0" />
          <p className="text-xs text-slate-400 leading-relaxed">
            QR codes can hide malicious URLs. Always scan before opening. If the QR code leads to a login page or asks for personal information, verify the source independently rather than trusting the code.
          </p>
        </div>
      </Card>
    </div>
  );
}

function ManualQrInput({ onScan, loading }: { onScan: (url: string) => void; loading: boolean }) {
  const [url, setUrl] = useState('');
  return (
    <div className="flex gap-2">
      <Input
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="https://url-from-qr-code.com"
      />
      <Button size="sm" disabled={!url.trim() || loading} onClick={() => onScan(url.trim())}>
        <ShieldCheck size={14} /> Check
      </Button>
    </div>
  );
}

// ==================== PASSWORD TOOLS ====================
function PasswordTools() {
  const [mode, setMode] = useState<'check' | 'generate'>('check');

  return (
    <div className="space-y-5">
      <div className="flex gap-1.5">
        <button
          onClick={() => setMode('check')}
          className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition ${
            mode === 'check' ? 'bg-cyan-400/10 text-cyan-200 border border-cyan-400/30' : 'bg-veil-800/60 text-slate-400 border border-transparent'
          }`}
        >
          <ShieldCheck size={15} /> Strength checker
        </button>
        <button
          onClick={() => setMode('generate')}
          className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition ${
            mode === 'generate' ? 'bg-cyan-400/10 text-cyan-200 border border-cyan-400/30' : 'bg-veil-800/60 text-slate-400 border border-transparent'
          }`}
        >
          <Zap size={15} /> Generator
        </button>
      </div>

      {mode === 'check' ? <PasswordChecker /> : <PasswordGenerator />}
    </div>
  );
}

function PasswordChecker() {
  const [password, setPassword] = useState('');
  const [show, setShow] = useState(false);

  const analysis = analyzePassword(password);

  return (
    <div className="space-y-5">
      <Card className="p-5">
        <SectionTitle
          title="Password Strength Checker"
          subtitle="Check how strong a password is — evaluation runs entirely in your browser"
          icon={<ShieldCheck size={18} />}
        />
        <div className="space-y-4">
          <div>
            <Label>Password</Label>
            <div className="relative">
              <KeyRound size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <Input
                type={show ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Type a password to check"
                className="pl-9 pr-10"
              />
              <button
                onClick={() => setShow(!show)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
              >
                {show ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
          </div>

          {password && (
            <>
              {/* Strength bar */}
              <div>
                <div className="flex items-center justify-between text-sm mb-2">
                  <span className="text-slate-300">Strength</span>
                  <span className={`font-medium ${analysis.color}`}>{analysis.label}</span>
                </div>
                <div className="h-2 rounded-full bg-veil-800 overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${analysis.barColor}`}
                    style={{ width: `${analysis.score}%` }}
                  />
                </div>
                <div className="flex items-center justify-between mt-1.5 text-[11px] text-slate-500">
                  <span>Crack time (estimate): {analysis.crackTime}</span>
                  <span>{analysis.score}/100</span>
                </div>
              </div>

              {/* Checklist */}
              <div className="grid grid-cols-2 gap-2">
                {analysis.checks.map((c) => (
                  <div
                    key={c.label}
                    className={`flex items-center gap-2 rounded-lg border p-2.5 text-xs ${
                      c.passed ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-200' : 'border-slate-700/60 bg-veil-800/40 text-slate-400'
                    }`}
                  >
                    {c.passed ? <CheckCircle2 size={13} className="shrink-0" /> : <X size={13} className="shrink-0" />}
                    {c.label}
                  </div>
                ))}
              </div>

              {/* Warnings */}
              {analysis.warnings.length > 0 && (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3.5">
                  <div className="flex items-start gap-2.5">
                    <AlertTriangle size={15} className="text-rose-300 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-xs font-medium text-rose-200 mb-1">Warnings</div>
                      <ul className="space-y-1">
                        {analysis.warnings.map((w, i) => (
                          <li key={i} className="text-xs text-slate-300">{w}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}

              <p className="text-[11px] text-slate-500">
                Your password is never sent to any server. This check runs entirely in your browser. No password is stored.
              </p>
            </>
          )}
        </div>
      </Card>
    </div>
  );
}

interface PasswordAnalysis {
  score: number;
  label: string;
  color: string;
  barColor: string;
  crackTime: string;
  checks: { label: string; passed: boolean }[];
  warnings: string[];
}

function analyzePassword(password: string): PasswordAnalysis {
  if (!password) {
    return { score: 0, label: '—', color: 'text-slate-400', barColor: 'bg-slate-700', crackTime: '—', checks: [], warnings: [] };
  }

  let score = 0;
  const checks: { label: string; passed: boolean }[] = [];
  const warnings: string[] = [];

  // Length
  const length = password.length;
  if (length >= 12) { score += 25; checks.push({ label: 'At least 12 characters', passed: true }); }
  else if (length >= 8) { score += 15; checks.push({ label: 'At least 12 characters', passed: false }); }
  else { score += 5; checks.push({ label: 'At least 12 characters', passed: false }); }
  if (length < 8) warnings.push('Password is shorter than 8 characters — this is very easy to crack.');

  // Character variety
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSymbol = /[^a-zA-Z0-9]/.test(password);

  if (hasLower) { score += 10; checks.push({ label: 'Lowercase letters', passed: true }); }
  else checks.push({ label: 'Lowercase letters', passed: false });

  if (hasUpper) { score += 10; checks.push({ label: 'Uppercase letters', passed: true }); }
  else checks.push({ label: 'Uppercase letters', passed: false });

  if (hasDigit) { score += 10; checks.push({ label: 'Numbers', passed: true }); }
  else checks.push({ label: 'Numbers', passed: false });

  if (hasSymbol) { score += 15; checks.push({ label: 'Symbols (!@#$…)', passed: true }); }
  else checks.push({ label: 'Symbols (!@#$…)', passed: false });

  // Variety bonus
  const variety = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
  score += variety * 3;

  // Common patterns
  if (/^123|abc|qwe|password|letmein|welcome|admin/i.test(password)) {
    score -= 30;
    warnings.push('Contains a common password pattern. These are in every attacker\'s dictionary.');
  }
  if (/^(.)\1+$/.test(password)) {
    score -= 20;
    warnings.push('All characters are the same — trivially cracked.');
  }
  if (/^\d+$/.test(password)) {
    score -= 15;
    warnings.push('Numbers only — vulnerable to brute force.');
  }
  if (/^[a-z]+$/i.test(password)) {
    score -= 10;
    warnings.push('Letters only — add numbers and symbols for much better security.');
  }

  // Repeated patterns
  if (/(.{2,})\1{2,}/.test(password)) {
    score -= 10;
    warnings.push('Contains repeated sequences (e.g. "abcabc").');
  }

  score = Math.max(0, Math.min(100, score));

  // Crack time estimate (rough — based on character space and length)
  let charsetSize = 0;
  if (hasLower) charsetSize += 26;
  if (hasUpper) charsetSize += 26;
  if (hasDigit) charsetSize += 10;
  if (hasSymbol) charsetSize += 32;
  charsetSize = Math.max(1, charsetSize);
  const combinations = Math.pow(charsetSize, length);
  const guessesPerSecond = 10_000_000_000; // 10 billion/sec for offline attack
  const seconds = combinations / guessesPerSecond / 2; // average = half the space
  const crackTime = formatCrackTime(seconds);

  let label: string, color: string, barColor: string;
  if (score < 25) { label = 'Very weak'; color = 'text-rose-300'; barColor = 'bg-rose-500'; }
  else if (score < 45) { label = 'Weak'; color = 'text-orange-300'; barColor = 'bg-orange-500'; }
  else if (score < 65) { label = 'Fair'; color = 'text-amber-300'; barColor = 'bg-amber-500'; }
  else if (score < 85) { label = 'Strong'; color = 'text-cyan-300'; barColor = 'bg-cyan-500'; }
  else { label = 'Very strong'; color = 'text-emerald-300'; barColor = 'bg-emerald-500'; }

  return { score, label, color, barColor, crackTime, checks, warnings };
}

function formatCrackTime(seconds: number): string {
  if (seconds < 1) return 'Instant';
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 2592000) return `${Math.round(seconds / 86400)} days`;
  if (seconds < 31536000) return `${Math.round(seconds / 2592000)} months`;
  const years = seconds / 31536000;
  if (years < 1000) return `${Math.round(years)} years`;
  if (years < 1_000_000) return `${Math.round(years / 1000)}K years`;
  if (years < 1_000_000_000) return `${Math.round(years / 1_000_000)}M years`;
  return 'Centuries+';
}

function PasswordGenerator() {
  const [length, setLength] = useState(16);
  const [uppercase, setUppercase] = useState(true);
  const [lowercase, setLowercase] = useState(true);
  const [numbers, setNumbers] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(true);
  const [password, setPassword] = useState('');
  const [copied, setCopied] = useState(false);

  const generate = useCallback(() => {
    let charset = '';
    const ambiguous = 'Il1O0o';

    if (lowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (numbers) charset += '0123456789';
    if (symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (excludeAmbiguous) {
      charset = charset.split('').filter((c) => !ambiguous.includes(c)).join('');
    }

    if (!charset) {
      setPassword('');
      return;
    }

    // Use crypto.getRandomValues for cryptographically secure randomness
    const arr = new Uint32Array(length);
    crypto.getRandomValues(arr);
    let result = '';
    for (let i = 0; i < length; i++) {
      result += charset[arr[i] % charset.length];
    }
    setPassword(result);
    setCopied(false);
  }, [length, uppercase, lowercase, numbers, symbols, excludeAmbiguous]);

  useEffect(() => { generate(); }, [generate]);

  async function copy() {
    if (!password) return;
    try {
      await navigator.clipboard.writeText(password);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback
    }
  }

  const strength = analyzePassword(password);

  return (
    <div className="space-y-5">
      <Card className="p-5">
        <SectionTitle
          title="Secure Password Generator"
          subtitle="Generate cryptographically random passwords using your browser's secure random source"
          icon={<Zap size={18} />}
        />

        {/* Generated password */}
        <div className="rounded-lg border border-slate-700/80 bg-veil-950/60 p-4 mb-5">
          <div className="flex items-center gap-2">
            <code className="flex-1 text-lg font-mono-tight text-cyan-200 break-all">
              {password || 'Select at least one character type'}
            </code>
            <button
              onClick={copy}
              disabled={!password}
              className="shrink-0 rounded-lg p-2 text-slate-400 hover:text-cyan-300 hover:bg-veil-800/60 transition disabled:opacity-30"
              title="Copy password"
            >
              {copied ? <CheckCircle2 size={18} className="text-emerald-300" /> : <Copy size={18} />}
            </button>
            <button
              onClick={generate}
              className="shrink-0 rounded-lg p-2 text-slate-400 hover:text-cyan-300 hover:bg-veil-800/60 transition"
              title="Generate new"
            >
              <RefreshCw size={18} />
            </button>
          </div>
          {password && (
            <div className="mt-3 flex items-center gap-3">
              <div className="flex-1 h-1.5 rounded-full bg-veil-800 overflow-hidden">
                <div className={`h-full ${strength.barColor} transition-all duration-300`} style={{ width: `${strength.score}%` }} />
              </div>
              <span className={`text-xs font-medium ${strength.color}`}>{strength.label}</span>
            </div>
          )}
        </div>

        {/* Options */}
        <div className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <Label>Length</Label>
              <span className="text-sm text-cyan-300 font-mono-tight">{length}</span>
            </div>
            <input
              type="range"
              min="8"
              max="64"
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
              className="w-full accent-cyan-400"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <Toggle label="Uppercase (A-Z)" checked={uppercase} onChange={setUppercase} />
            <Toggle label="Lowercase (a-z)" checked={lowercase} onChange={setLowercase} />
            <Toggle label="Numbers (0-9)" checked={numbers} onChange={setNumbers} />
            <Toggle label="Symbols (!@#$)" checked={symbols} onChange={setSymbols} />
            <Toggle label="Exclude ambiguous (Il1O0)" checked={excludeAmbiguous} onChange={setExcludeAmbiguous} />
          </div>

          <Button full onClick={generate}>
            <RefreshCw size={15} /> Generate new password
          </Button>
        </div>

        <p className="text-[11px] text-slate-500 mt-4">
          Generated using <span className="text-slate-400">crypto.getRandomValues</span> — cryptographically secure. The password is never sent to any server.
        </p>
      </Card>
    </div>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className={`flex items-center gap-2.5 rounded-lg border p-3 text-sm transition text-left ${
        checked ? 'border-cyan-400/30 bg-cyan-500/5 text-slate-200' : 'border-slate-700/60 bg-veil-800/40 text-slate-400'
      }`}
    >
      <div className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 transition ${
        checked ? 'bg-cyan-400 border-cyan-400 text-veil-950' : 'border-slate-600'
      }`}>
        {checked && <CheckCircle2 size={12} />}
      </div>
      {label}
    </button>
  );
}
