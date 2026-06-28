import React from 'react';
import ReactDOM from 'react-dom/client';
import { invoke } from '@tauri-apps/api/core';
import { Shield, Settings, Database, Play, FileSearch, Activity } from 'lucide-react';
import './styles.css';

type HashResult = { path: string; file_name: string; size_bytes: number; sha256: string; sha1: string; md5: string };
type SettingsModel = { theme: string; default_duration_seconds: number; default_networking_enabled: boolean; virustotal_api_key: string; allow_unknown_file_upload: boolean; keep_raw_run_folders: boolean };

type RunItem = { id: string; original_filename: string; sha256: string; version_label?: string; sandbox_profile: string; started_at: string; status: string };

const defaultSettings: SettingsModel = { theme: 'system', default_duration_seconds: 60, default_networking_enabled: false, virustotal_api_key: '', allow_unknown_file_upload: false, keep_raw_run_folders: true };

function App() {
  const [page, setPage] = React.useState<'analyze'|'runs'|'settings'>('analyze');
  const [settings, setSettings] = React.useState<SettingsModel>(defaultSettings);
  const [runs, setRuns] = React.useState<RunItem[]>([]);

  React.useEffect(() => {
    invoke<string>('init_database').catch(console.error);
    invoke<SettingsModel>('get_settings').then(setSettings).catch(console.error);
    refreshRuns();
  }, []);

  React.useEffect(() => {
    document.documentElement.dataset.theme = settings.theme === 'system' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : settings.theme;
  }, [settings.theme]);

  async function refreshRuns() {
    const data = await invoke<RunItem[]>('list_runs').catch(() => []);
    setRuns(data);
  }

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><Shield size={26}/><div><strong>Sandbox Analyzer</strong><span>Windows behavioural testing</span></div></div>
      <button className={page === 'analyze' ? 'nav active' : 'nav'} onClick={() => setPage('analyze')}><Play size={18}/> Analyze</button>
      <button className={page === 'runs' ? 'nav active' : 'nav'} onClick={() => { setPage('runs'); refreshRuns(); }}><Database size={18}/> Runs</button>
      <button className={page === 'settings' ? 'nav active' : 'nav'} onClick={() => setPage('settings')}><Settings size={18}/> Settings</button>
    </aside>
    <main className="content">
      {page === 'analyze' && <Analyze settings={settings} onRunCreated={refreshRuns}/>} 
      {page === 'runs' && <Runs runs={runs}/>} 
      {page === 'settings' && <SettingsPage settings={settings} setSettings={setSettings}/>} 
    </main>
  </div>;
}

function Analyze({settings, onRunCreated}: {settings: SettingsModel; onRunCreated: () => void}) {
  const [path, setPath] = React.useState('');
  const [hash, setHash] = React.useState<HashResult | null>(null);
  const [duration, setDuration] = React.useState(settings.default_duration_seconds);
  const [networking, setNetworking] = React.useState(settings.default_networking_enabled);
  const [versionLabel, setVersionLabel] = React.useState('');
  const [status, setStatus] = React.useState('Ready');
  const [vt, setVt] = React.useState<any>(null);

  React.useEffect(() => { setDuration(settings.default_duration_seconds); setNetworking(settings.default_networking_enabled); }, [settings.default_duration_seconds, settings.default_networking_enabled]);

  async function calculateHash() {
    setStatus('Calculating hashes...');
    const result = await invoke<HashResult>('hash_file', { path });
    setHash(result);
    setStatus('Hash calculated');
  }

  async function lookupVt() {
    if (!hash) return;
    setStatus('Checking VirusTotal...');
    const result = await invoke('lookup_hash', { apiKey: settings.virustotal_api_key, sha256: hash.sha256 });
    setVt(result);
    setStatus('VirusTotal lookup complete');
  }

  async function launch() {
    setStatus('Preparing and launching Windows Sandbox...');
    const result: any = await invoke('prepare_and_launch_sandbox', { request: { sample_path: path, duration_seconds: Number(duration), networking_enabled: networking, version_label: versionLabel || null } });
    setStatus(`Sandbox launched. Run folder: ${result.run_folder}. Import summary.json from output when complete.`);
    onRunCreated();
  }

  return <section>
    <div className="hero"><div><p className="eyebrow">New analysis</p><h1>Run an installer in Windows Sandbox</h1><p>Select a file, enrich it with VirusTotal, and launch a disposable sandbox collection run.</p></div><Activity size={42}/></div>
    <div className="grid two">
      <div className="card">
        <h2><FileSearch size={20}/> Sample</h2>
        <label>File path</label>
        <input value={path} onChange={e => setPath(e.target.value)} placeholder="C:\\Users\\Phil\\Downloads\\installer.exe" />
        <div className="buttonRow"><button onClick={calculateHash} disabled={!path}>Calculate hash</button><button onClick={lookupVt} disabled={!hash || !settings.virustotal_api_key}>VirusTotal lookup</button></div>
        {hash && <div className="facts"><span>Name</span><b>{hash.file_name}</b><span>SHA256</span><code>{hash.sha256}</code><span>Size</span><b>{Math.round(hash.size_bytes / 1024)} KB</b></div>}
        {vt && <pre className="json">{JSON.stringify(vt, null, 2)}</pre>}
      </div>
      <div className="card">
        <h2>Analysis options</h2>
        <label>Duration, seconds</label><input type="number" value={duration} onChange={e => setDuration(Number(e.target.value))}/>
        <label>Version label</label><input value={versionLabel} onChange={e => setVersionLabel(e.target.value)} placeholder="e.g. 1.2.3"/>
        <label className="check"><input type="checkbox" checked={networking} onChange={e => setNetworking(e.target.checked)}/> Enable sandbox networking</label>
        <button className="primary" onClick={launch} disabled={!hash}>Run analysis</button>
        <p className="status">{status}</p>
      </div>
    </div>
  </section>;
}

function Runs({runs}: {runs: RunItem[]}) {
  return <section><div className="pageTitle"><h1>Analysis runs</h1><p>Stored runs and imported summaries.</p></div><div className="card"><table><thead><tr><th>Started</th><th>File</th><th>Version</th><th>Profile</th><th>Status</th><th>SHA256</th></tr></thead><tbody>{runs.map(r => <tr key={r.id}><td>{r.started_at}</td><td>{r.original_filename}</td><td>{r.version_label || '-'}</td><td>{r.sandbox_profile}</td><td>{r.status}</td><td><code>{r.sha256.slice(0, 18)}…</code></td></tr>)}</tbody></table>{runs.length === 0 && <p className="muted">No runs imported yet.</p>}</div></section>;
}

function SettingsPage({settings, setSettings}: {settings: SettingsModel; setSettings: (s: SettingsModel) => void}) {
  async function save(next: SettingsModel) { setSettings(next); await invoke('save_settings', { settings: next }); }
  async function clearDb() { if (confirm('Clear all stored analysis data?')) await invoke('clear_database'); }
  return <section><div className="pageTitle"><h1>Settings</h1><p>Appearance, storage, VirusTotal and default sandbox behaviour.</p></div><div className="grid two"><div className="card"><h2>Appearance</h2><label>Theme</label><select value={settings.theme} onChange={e => save({...settings, theme: e.target.value})}><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select><h2>Sandbox defaults</h2><label>Default duration</label><input type="number" value={settings.default_duration_seconds} onChange={e => save({...settings, default_duration_seconds: Number(e.target.value)})}/><label className="check"><input type="checkbox" checked={settings.default_networking_enabled} onChange={e => save({...settings, default_networking_enabled: e.target.checked})}/> Enable networking by default</label></div><div className="card"><h2>VirusTotal</h2><label>API key</label><input type="password" value={settings.virustotal_api_key} onChange={e => save({...settings, virustotal_api_key: e.target.value})}/><label className="check"><input type="checkbox" checked={settings.allow_unknown_file_upload} onChange={e => save({...settings, allow_unknown_file_upload: e.target.checked})}/> Allow upload of unknown files</label><h2>Storage</h2><label className="check"><input type="checkbox" checked={settings.keep_raw_run_folders} onChange={e => save({...settings, keep_raw_run_folders: e.target.checked})}/> Keep raw sandbox run folders</label><button className="danger" onClick={clearDb}>Clear database</button></div></div></section>;
}

ReactDOM.createRoot(document.getElementById('root')!).render(<App />);
