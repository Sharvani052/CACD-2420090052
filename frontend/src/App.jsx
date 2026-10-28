import { useEffect, useState } from 'react'
import './App.css'

const API = import.meta.env.VITE_API_URL || 'http://localhost:5000/api'

async function api(path, options = {}, token) {
  const response = await fetch(`${API}${path}`, { ...options, headers: { ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers } })
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).message || `Request failed (${response.status})`)
  return response
}

function riskFrom(response) {
  let factors = []
  try { factors = JSON.parse(decodeURIComponent(response.headers.get('X-Risk-Factors') || '[]')) } catch { factors = ['Risk factors unavailable'] }
  const decision = response.headers.get('X-Risk-Decision') || 'UNKNOWN'
  return { score: response.headers.get('X-Risk-Score') ?? '—', level: response.headers.get('X-Risk-Level') || 'UNKNOWN', decision, factors, delivered: decision === 'DECOY' ? 'DECOY FILE delivered' : 'REAL FILE delivered' }
}

function ThemeToggle({ theme, setTheme }) {
  return <div className="theme-toggle" aria-label="Color theme"><button className={theme === 'light' ? 'active' : ''} onClick={() => setTheme('light')}>☀ Light</button><button className={theme === 'dark' ? 'active' : ''} onClick={() => setTheme('dark')}>◐ Dark</button></div>
}

function DecisionPanel({ decision }) {
  if (!decision) return null
  return <section className={`decision-panel ${decision.level.toLowerCase()} ${decision.decision.toLowerCase()}`}><div><p className="eyebrow">Security Decision</p><h2>{decision.delivered}</h2></div><div className="decision-grid"><span><b>Risk score</b>{decision.score}</span><span><b>Risk level</b><em>{decision.level}</em></span><span><b>Decision</b><em>{decision.decision}</em></span></div><div className="factors"><b>Risk factors</b><ul>{decision.factors.map((factor) => <li key={factor}>{factor}</li>)}</ul></div></section>
}

function App() {
  const [session, setSession] = useState(() => JSON.parse(localStorage.getItem('ads-session') || 'null'))
  const [theme, setTheme] = useState(() => localStorage.getItem('ads-theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'))
  const [email, setEmail] = useState(''); const [password, setPassword] = useState(''); const [files, setFiles] = useState([]); const [dashboard, setDashboard] = useState(null); const [message, setMessage] = useState(''); const [decision, setDecision] = useState(null); const [busy, setBusy] = useState(false)
  useEffect(() => { document.documentElement.dataset.theme = theme; localStorage.setItem('ads-theme', theme) }, [theme])
  const loadFiles = async () => { if (session) setFiles((await (await api('/files', {}, session.token)).json()).files) }
  const loadDashboard = async () => { if (session?.user.role === 'ADMIN') setDashboard((await (await api('/admin/dashboard', {}, session.token)).json()).dashboard) }
  useEffect(() => {
    let cancelled = false
    async function load() { if (!session) return; try { const fileResult = await (await api('/files', {}, session.token)).json(); if (!cancelled) setFiles(fileResult.files); if (session.user.role === 'ADMIN') { const dashboardResult = await (await api('/admin/dashboard', {}, session.token)).json(); if (!cancelled) setDashboard(dashboardResult.dashboard) } } catch (error) { if (!cancelled) setMessage(error.message) } }
    load(); return () => { cancelled = true }
  }, [session])
  const login = async (event) => { event.preventDefault(); setBusy(true); setMessage(''); try { const result = await (await api('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) })).json(); const value = { token: result.token, user: result.user }; localStorage.setItem('ads-session', JSON.stringify(value)); setSession(value) } catch (error) { setMessage(error.message) } finally { setBusy(false) } }
  const upload = async (event) => { const file = event.target.files?.[0]; if (!file) return; setBusy(true); setMessage(''); try { const form = new FormData(); form.append('file', file); const result = await (await api('/files/upload', { method: 'POST', body: form }, session.token)).json(); setMessage(`${result.message}: ${result.file.originalName}`); await loadFiles() } catch (error) { setMessage(error.message) } finally { setBusy(false); event.target.value = '' } }
  const download = async (file) => { setBusy(true); setMessage(''); try { const response = await api(`/files/${file.id}`, {}, session.token); const currentDecision = riskFrom(response); const url = URL.createObjectURL(await response.blob()); const link = document.createElement('a'); link.href = url; link.download = file.original_name; link.click(); URL.revokeObjectURL(url); setDecision(currentDecision); setMessage(currentDecision.delivered); await loadFiles(); await loadDashboard() } catch (error) { setMessage(error.message) } finally { setBusy(false) } }
  if (!session) return <main className="auth"><header className="auth-header"><p className="eyebrow">Adaptive Decoy Security</p><ThemeToggle theme={theme} setTheme={setTheme} /></header><section className="hero-card"><p className="eyebrow">Behavioral risk protection</p><h1>Protected-file access that adapts to behavior.</h1><p>Authenticate, encrypt, verify integrity, and deliver a decoy only when multiple application-level signals indicate high risk.</p></section><form onSubmit={login}><h2>Sign in</h2><label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label><label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label><button disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>{message && <p className="notice">{message}</p>}</form></main>
  return <main><header><div><p className="eyebrow">Adaptive Decoy Security</p><h1>Secure file workspace</h1><p>{session.user.name} · {session.user.role}</p></div><div className="header-actions"><ThemeToggle theme={theme} setTheme={setTheme} /><button className="secondary" onClick={() => { localStorage.removeItem('ads-session'); setSession(null) }}>Sign out</button></div></header>{message && <p className="notice">{message}</p>}<DecisionPanel decision={decision} />{dashboard && <section><h2>Security dashboard</h2><div className="cards">{Object.entries(dashboard).map(([label, value]) => <article key={label}><strong>{value}</strong><span>{label.replace(/([A-Z])/g, ' $1')}</span></article>)}</div></section>}<section><div className="section-title"><div><h2>My encrypted files</h2><p>Each delivery checks AES-GCM authentication and SHA-256 integrity before exposure.</p></div><label className="upload">Upload file<input type="file" onChange={upload} disabled={busy} /></label></div><div className="file-list">{files.length ? files.map((file) => <article className="file" key={file.id}><div><strong>{file.original_name}</strong><span>{Number(file.file_size).toLocaleString()} bytes · {file.mime_type || 'unknown type'}</span></div><button onClick={() => download(file)} disabled={busy}>Download</button></article>) : <p>No encrypted files yet.</p>}</div></section></main>
}

export default App
