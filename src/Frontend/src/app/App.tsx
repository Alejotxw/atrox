import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldAlert, 
  TerminalSquare, 
  Database, 
  Radar, 
  ScanLine, 
  Cpu, 
  History,
  Play,
  CheckCircle2,
  AlertTriangle,
  Info,
  Clock,
  ShieldCheck,
  Server,
  Network,
  FileText,
  Loader2,
  Search,
  Activity,
  Lock,
  MessageSquare,
  Calendar,
  ChevronRight,
  Zap,
  Target,
  Terminal
} from 'lucide-react';

// --- Datos Iniciales Simulados para la vista inicial ---
const INITIAL_METRICS = { subdomains: "42", ports: "8", vulns: "3", report: "Generando" };
const INITIAL_LOGS = [
  { id: 1, time: '14:02:11', module: 'INFO', color: 'text-blue-400', text: 'Starting AI-Pentest Framework v1.0' },
  { id: 2, time: '14:02:12', module: 'NMAP', color: 'text-purple-400', text: 'Scanning target: corp.internal.uide.edu.ec' },
  { id: 3, time: '14:02:45', module: 'NMAP', color: 'text-purple-400', text: 'Discovered open port 80/tcp (http)' },
  { id: 4, time: '14:02:45', module: 'NMAP', color: 'text-purple-400', text: 'Discovered open port 443/tcp (https)' },
  { id: 5, time: '14:02:45', module: 'NMAP', color: 'text-purple-400', text: 'Discovered open port 3306/tcp (mysql)' },
  { id: 6, time: '14:03:10', module: 'NUCLEI', color: 'text-emerald-400', text: 'Loading templates for web vulnerabilities...' },
  { id: 7, time: '14:03:15', module: 'NUCLEI', color: 'text-emerald-400', isCritical: true, text: 'SQL Injection found on /login.php (parameter \'user\')' },
  { id: 8, time: '14:03:18', module: 'NUCLEI', color: 'text-emerald-400', isCritical: true, text: 'Apache Path Traversal (CVE-2021-41773) in /cgi-bin/' },
  { id: 9, time: '14:03:22', module: 'NUCLEI', color: 'text-emerald-400', isMedium: true, text: 'Default credentials allowed on MySQL Port 3306' },
  { id: 10, time: '14:03:25', module: 'OLLAMA', color: 'text-[#D4AF37]', text: 'Feeding findings to Local Llama 3 Engine for correlation...' },
  { id: 11, time: '14:03:28', module: 'OLLAMA', color: 'text-[#D4AF37]', text: 'Generating mitigation strategies based on CVE databases...' }
];
const INITIAL_FINDINGS = [
  { id: 'VULN-001', name: 'SQL Injection (Blind)', vector: 'HTTP POST /login.php', severity: 'Crítico', status: 'checked' },
  { id: 'VULN-002', name: 'Apache Path Traversal (CVE-2021-41773)', vector: 'GET /cgi-bin/', severity: 'Crítico', status: 'checked' },
  { id: 'VULN-003', name: 'Default DB Credentials', vector: 'MySQL Port 3306', severity: 'Medio', status: 'unchecked' },
  { id: 'VULN-004', name: 'Open Directory Listing', vector: 'GET /assets/uploads/', severity: 'Info', status: 'na' }
];

export default function App() {
  // --- ESTADOS INTERACTIVOS ---
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [targetUrl, setTargetUrl] = useState('corp.internal.uide.edu.ec');
  const [isAuditing, setIsAuditing] = useState(false);
  
  const [metrics, setMetrics] = useState(INITIAL_METRICS);
  const [logs, setLogs] = useState(INITIAL_LOGS);
  const [findings, setFindings] = useState(INITIAL_FINDINGS);
  const [showInsights, setShowInsights] = useState(true);
  
  const logsEndRef = useRef<HTMLDivElement>(null);

  // --- AUTO-SCROLL DE LA CONSOLA ---
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // --- UTILIDAD PARA SIMULAR RETRASOS ---
  const delay = (ms: number) => new Promise(res => setTimeout(res, ms));
  const getCurrentTime = () => new Date().toTimeString().split(' ')[0];

  // --- MOTOR DE SIMULACIÓN DE AUDITORÍA ---
  const handleStartAudit = async () => {
    if (isAuditing || !targetUrl.trim()) return;
    
    setIsAuditing(true);
    setLogs([]);
    setFindings([]);
    setShowInsights(false);
    setMetrics({ subdomains: "0", ports: "0", vulns: "0", report: "Iniciando" });
    
    const addLog = (module: string, color: string, text: string, isCritical = false, isMedium = false) => {
      setLogs(prev => [...prev, { id: Date.now() + Math.random(), time: getCurrentTime(), module, color, text, isCritical, isMedium }]);
    };

    // Paso 1: Inicio
    await delay(500);
    addLog('INFO', 'text-blue-400', 'Starting AI-Pentest Framework v1.0');
    
    // Paso 2: NMAP
    await delay(1200);
    addLog('NMAP', 'text-purple-400', `Scanning target: ${targetUrl}`);
    setMetrics(m => ({ ...m, ports: "Scanning..." }));
    
    await delay(1500);
    addLog('NMAP', 'text-purple-400', 'Discovered open port 80/tcp (http)');
    await delay(400);
    addLog('NMAP', 'text-purple-400', 'Discovered open port 443/tcp (https)');
    await delay(600);
    addLog('NMAP', 'text-purple-400', 'Discovered open port 3306/tcp (mysql)');
    setMetrics(m => ({ ...m, ports: "3" }));

    // Paso 3: Subfinder
    await delay(1200);
    addLog('SUBFIND', 'text-blue-400', 'Discovering subdomains...');
    setMetrics(m => ({ ...m, subdomains: "Buscando..." }));
    
    await delay(1800);
    setMetrics(m => ({ ...m, subdomains: "42" }));
    
    // Paso 4: Nuclei (Vulnerabilidades)
    await delay(800);
    addLog('NUCLEI', 'text-emerald-400', 'Loading templates for web vulnerabilities...');
    
    await delay(2000);
    addLog('NUCLEI', 'text-emerald-400', `SQL Injection found on /login.php (parameter 'user')`, true);
    setFindings(prev => [...prev, { id: 'VULN-001', name: 'SQL Injection (Blind)', vector: 'HTTP POST /login.php', severity: 'Crítico', status: 'unchecked' }]);
    setMetrics(m => ({ ...m, vulns: "1" }));
    
    await delay(1200);
    addLog('NUCLEI', 'text-emerald-400', 'Apache Path Traversal (CVE-2021-41773) in /cgi-bin/', true);
    setFindings(prev => [...prev, { id: 'VULN-002', name: 'Apache Path Traversal (CVE-2021-41773)', vector: 'GET /cgi-bin/', severity: 'Crítico', status: 'unchecked' }]);
    setMetrics(m => ({ ...m, vulns: "2" }));

    await delay(1500);
    addLog('NUCLEI', 'text-emerald-400', 'Default credentials allowed on MySQL Port 3306', false, true);
    setFindings(prev => [...prev, { id: 'VULN-003', name: 'Default DB Credentials', vector: 'MySQL Port 3306', severity: 'Medio', status: 'unchecked' }]);
    setFindings(prev => [...prev, { id: 'VULN-004', name: 'Open Directory Listing', vector: 'GET /assets/uploads/', severity: 'Info', status: 'na' }]);
    setMetrics(m => ({ ...m, vulns: "3", report: "Analizando" }));

    // Paso 5: Ollama Insights
    await delay(1500);
    addLog('OLLAMA', 'text-[#D4AF37]', 'Feeding findings to Local Llama 3 Engine for correlation...');
    
    await delay(2000);
    addLog('OLLAMA', 'text-[#D4AF37]', 'Generating mitigation strategies based on CVE databases...');
    
    await delay(1500);
    setShowInsights(true);
    setMetrics(m => ({ ...m, report: "Completado" }));
    setIsAuditing(false);
  };

  // --- VALIDAR VULNERABILIDAD MANUALMENTE EN TABLA ---
  const handleValidateFinding = (id: string) => {
    setFindings(prev => prev.map(f => f.id === id && f.status === 'unchecked' ? { ...f, status: 'checked' } : f));
  };

  return (
    <div className="flex h-screen w-full bg-[#0F172A] text-slate-300 font-sans overflow-hidden">
      
      {/* 1. Sidebar Izquierdo - Navegación y Branding */}
      <aside className="w-[300px] bg-[#0B1121] border-r border-slate-800 flex flex-col shrink-0">
        <div className="p-6 border-b border-slate-800">
          <div className="flex items-center gap-4 mb-3">
            <div className="w-12 h-12 rounded-xl bg-[#7A1C3E] flex items-center justify-center shadow-lg shadow-[#7A1C3E]/20">
              <ShieldAlert className="text-white w-7 h-7" />
            </div>
            <div>
              <h1 className="text-white font-bold text-xl leading-none mb-1">UIDE</h1>
              <p className="text-[10px] text-slate-400 font-semibold tracking-wider uppercase leading-tight">Facultad de Ciencias<br/>Técnicas</p>
            </div>
          </div>
          <p className="text-xs text-[#D4AF37] mt-2 italic font-medium">Powered by Arizona State University</p>
        </div>
        
        <div className="p-5 flex-1 overflow-y-auto">
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-4 px-2">AI-Pentest Framework v1.0</h2>
          <nav className="space-y-1.5">
            <NavItem icon={<Radar />} label="Dashboard" active={activeTab === 'Dashboard'} onClick={() => setActiveTab('Dashboard')} />
            <NavItem icon={<Network />} label="Reconocimiento (Nmap)" active={activeTab === 'Reconocimiento (Nmap)'} onClick={() => setActiveTab('Reconocimiento (Nmap)')} />
            <NavItem icon={<ScanLine />} label="Escaneo (Nuclei/SQLMap)" active={activeTab === 'Escaneo (Nuclei/SQLMap)'} onClick={() => setActiveTab('Escaneo (Nuclei/SQLMap)')} />
            <NavItem icon={<ShieldCheck />} label="Validación (Metasploit)" active={activeTab === 'Validación (Metasploit)'} onClick={() => setActiveTab('Validación (Metasploit)')} />
            <NavItem icon={<Cpu />} label="Motor Ollama IA" badge="Llama 3" active={activeTab === 'Motor Ollama IA'} onClick={() => setActiveTab('Motor Ollama IA')} />
            <NavItem icon={<History />} label="Historial SQLite" active={activeTab === 'Historial SQLite'} onClick={() => setActiveTab('Historial SQLite')} />
          </nav>
        </div>

        <div className="p-5 border-t border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center border border-slate-700">
              <span className="text-xs font-bold text-white">AD</span>
            </div>
            <div>
              <p className="text-sm font-medium text-white">Admin SecOps</p>
              <p className="text-xs text-slate-500">Nivel de Acceso: Root</p>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        
        {/* 2. Header Superior - Status del Sistema */}
        <header className="h-20 bg-[#1E293B]/80 backdrop-blur-md border-b border-slate-800 flex items-center justify-between px-8 shrink-0">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2.5 bg-[#0B1121] px-4 py-2 rounded-full border border-green-500/30 shadow-inner">
              <div className="w-2.5 h-2.5 rounded-full bg-green-500 animate-pulse shadow-[0_0_8px_rgba(34,197,94,0.6)]"></div>
              <span className="text-xs text-green-400 font-semibold tracking-wide">Ollama Local Engine: ONLINE (Llama 3)</span>
            </div>
            <div className="flex items-center gap-2.5 bg-[#0B1121] px-4 py-2 rounded-full border border-slate-700 shadow-inner">
              <Database className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-xs text-slate-300 font-semibold tracking-wide">Base de Datos SQLite: CONECTADA</span>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                <Network className="h-4 w-4 text-slate-500" />
              </div>
              <input 
                type="text" 
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={isAuditing}
                className="block w-72 pl-10 pr-4 py-2.5 border border-slate-700 rounded-lg leading-5 bg-[#0B1121] text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[#7A1C3E] focus:border-transparent sm:text-sm font-mono transition-shadow disabled:opacity-50"
                placeholder="Objetivo (IP o Dominio)"
              />
            </div>
            <button 
              onClick={handleStartAudit}
              disabled={isAuditing || !targetUrl.trim()}
              className="bg-[#7A1C3E] hover:bg-[#90244B] disabled:bg-[#7A1C3E]/50 disabled:cursor-not-allowed text-white px-5 py-2.5 rounded-lg text-sm font-semibold flex items-center gap-2.5 transition-all shadow-lg shadow-[#7A1C3E]/30 border border-[#7A1C3E] hover:border-[#A62A56] disabled:border-transparent"
            >
              {isAuditing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Auditoría en Curso...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  Iniciar Auditoría Automatizada
                </>
              )}
            </button>
          </div>
        </header>

        {/* Scrollable Dashboard Area */}
        <div className="flex-1 overflow-y-auto p-8 bg-[#0F172A]">
          <div className="max-w-[1600px] mx-auto space-y-8">
            
            {/* MAIN CONTENT VIEWS */}
            {activeTab === 'Dashboard' && (
              <>
                {/* 3. Panel Superior de Métricas */}
                <div className="grid grid-cols-4 gap-6 animate-in fade-in duration-300">
                  <MetricCard 
                    title="Subdominios Descubiertos" 
                    value={metrics.subdomains} 
                    module="Módulo Subfinder" 
                    icon={<Network />} 
                    color="blue" 
                  />
                  <MetricCard 
                    title="Puertos y Servicios" 
                    value={metrics.ports} 
                    module="Módulo Nmap" 
                    icon={<Server />} 
                    color="indigo" 
                  />
                  <MetricCard 
                    title="Vulnerabilidades Críticas" 
                    value={metrics.vulns} 
                    module="Módulo Nuclei" 
                    icon={<AlertTriangle />} 
                    color="red" 
                  />
                  <MetricCard 
                    title="Estado del Reporte" 
                    value={metrics.report} 
                    module="Módulo ReportLab" 
                    icon={<FileText />} 
                    color="gold" 
                  />
                </div>

                {/* 4. Área Central - El Núcleo del Proyecto */}
                <div className="grid grid-cols-3 gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500 delay-100 fill-mode-both">
                  
                  {/* Consola de Ejecución */}
                  <div className="col-span-2 bg-[#000000] border border-slate-800 rounded-xl overflow-hidden flex flex-col shadow-2xl relative">
                    <div className="absolute inset-0 bg-gradient-to-b from-transparent to-black/20 pointer-events-none"></div>
                    <div className="bg-[#1E293B] px-5 py-3 border-b border-slate-800 flex items-center justify-between z-10">
                      <div className="flex items-center gap-2.5">
                        <TerminalSquare className="w-4 h-4 text-slate-400" />
                        <span className="text-xs font-mono text-slate-300 font-semibold tracking-wide">Consola de Ejecución UNIX</span>
                      </div>
                      <div className="flex gap-2">
                        <div className="w-3 h-3 rounded-full bg-red-500/90 shadow-[0_0_5px_rgba(239,68,68,0.5)]"></div>
                        <div className="w-3 h-3 rounded-full bg-yellow-500/90 shadow-[0_0_5px_rgba(234,179,8,0.5)]"></div>
                        <div className="w-3 h-3 rounded-full bg-green-500/90 shadow-[0_0_5px_rgba(34,197,94,0.5)]"></div>
                      </div>
                    </div>
                    <div className="p-6 font-mono text-[13px] text-slate-300 leading-relaxed overflow-y-auto h-[420px] space-y-1.5 z-10 scroll-smooth">
                      <div className="text-slate-500">root@ai-pentest:~# ./run_audit.sh --target {targetUrl}</div>
                      {logs.map((log) => (
                        <div key={log.id} className="text-slate-500 animate-in fade-in slide-in-from-bottom-2 duration-300">
                          [{log.time}] <span className={`${log.color} font-semibold`}>[{log.module}]</span>{' '}
                          {log.isCritical && <span className="text-red-400 font-bold">[CRITICAL] </span>}
                          {log.isMedium && <span className="text-[#D4AF37] font-bold">[MEDIUM] </span>}
                          {log.text}
                        </div>
                      ))}
                      {isAuditing && (
                        <div className="flex items-center gap-2 mt-3">
                          <span className="text-green-400">root@ai-pentest:~#</span>
                          <span className="w-2.5 h-4 bg-slate-300 animate-pulse"></span>
                        </div>
                      )}
                      <div ref={logsEndRef} />
                    </div>
                  </div>

                  {/* Módulo de IA - Ollama Insights */}
                  <div className="col-span-1 bg-gradient-to-br from-[#1E293B] via-[#141E30] to-[#0B1121] border border-[#D4AF37]/50 rounded-xl overflow-hidden shadow-[0_0_25px_rgba(212,175,55,0.08)] flex flex-col relative">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-[#D4AF37]/5 blur-3xl rounded-full pointer-events-none"></div>
                    
                    <div className="px-6 py-4 border-b border-[#D4AF37]/20 flex justify-between items-center bg-[#D4AF37]/10 z-10">
                      <div className="flex items-center gap-3">
                        <div className="p-1.5 bg-[#D4AF37]/20 rounded-md">
                          <Cpu className="w-5 h-5 text-[#D4AF37]" />
                        </div>
                        <h3 className="font-bold text-white text-[15px]">Ollama Insights</h3>
                      </div>
                      <span className="text-[10px] bg-[#0B1121] text-[#D4AF37] px-2.5 py-1 rounded border border-[#D4AF37]/30 font-mono font-semibold tracking-wider">LLAMA-3-8B</span>
                    </div>
                    
                    <div className="p-6 flex-1 overflow-y-auto z-10 relative">
                      {!showInsights ? (
                        <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 animate-pulse">
                          <Cpu className="w-12 h-12 text-[#D4AF37]/30 mb-4" />
                          <p className="text-sm text-center px-4">Esperando resultados del escaneo para generar análisis...</p>
                        </div>
                      ) : (
                        <div className="animate-in fade-in slide-in-from-right-4 duration-700">
                          <h4 className="text-[15px] font-semibold text-white mb-4">Análisis Crítico de Riesgos</h4>
                          
                          <div className="mb-6 flex items-center justify-between bg-red-500/10 border border-red-500/20 rounded-lg p-4 shadow-inner">
                            <span className="text-xs text-slate-300 uppercase tracking-widest font-bold">Nivel de Amenaza Estimado</span>
                            <div className="flex items-center gap-2 text-red-500 font-black text-sm tracking-wide">
                              <AlertTriangle className="w-4 h-4 animate-bounce" />
                              CRÍTICO
                            </div>
                          </div>
                          
                          <div className="space-y-5">
                            <div className="relative">
                              <div className="absolute left-0 top-0 bottom-0 w-1 bg-[#D4AF37] rounded-l"></div>
                              <p className="text-[13px] text-slate-300 font-mono leading-relaxed bg-black/40 pl-5 pr-4 py-3 rounded border border-slate-700/50">
                                Se han detectado múltiples vectores de compromiso directo. La combinación de inyección SQL en <span className="text-red-300">/login.php</span> y vulnerabilidades de Path Traversal permite la ejecución remota de código (RCE).
                              </p>
                            </div>
                            
                            <div>
                              <h5 className="text-xs font-bold text-[#D4AF37] uppercase tracking-widest mb-3 flex items-center gap-2">
                                <ShieldCheck className="w-4 h-4" />
                                Recomendaciones (Mitigación)
                              </h5>
                              <ul className="space-y-3">
                                <li className="flex gap-3 text-[13px] bg-black/30 p-3.5 rounded-lg border border-slate-700/50 hover:border-slate-600 transition-colors">
                                  <span className="text-[#D4AF37] font-black font-mono">1.</span>
                                  <span className="text-slate-300 leading-relaxed">Actualizar servidor Apache (parchear <strong>CVE-2021-41773</strong>).</span>
                                </li>
                                <li className="flex gap-3 text-[13px] bg-black/30 p-3.5 rounded-lg border border-slate-700/50 hover:border-slate-600 transition-colors">
                                  <span className="text-[#D4AF37] font-black font-mono">2.</span>
                                  <span className="text-slate-300 leading-relaxed">Consultas parametrizadas en <code className="bg-black text-red-400 px-1.5 py-0.5 rounded font-mono text-xs border border-red-500/20">/login.php</code>.</span>
                                </li>
                              </ul>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* 5. Tabla Inferior - Trazabilidad de Hallazgos */}
                <div className="bg-[#1E293B] border border-slate-700 rounded-xl overflow-hidden shadow-lg animate-in fade-in slide-in-from-bottom-4 duration-500 delay-200 fill-mode-both">
                  <div className="px-6 py-5 border-b border-slate-700 bg-[#1E293B] flex items-center justify-between">
                    <h3 className="font-bold text-white text-[15px] flex items-center gap-2">
                      <Database className="w-4 h-4 text-[#7A1C3E]" />
                      Trazabilidad de Hallazgos
                    </h3>
                    <span className="text-xs text-slate-400 font-medium px-3 py-1 bg-slate-800 rounded-full border border-slate-700">
                      Mostrando {findings.length} vulnerabilidad{findings.length !== 1 ? 'es' : ''}
                    </span>
                  </div>
                  <div className="overflow-x-auto min-h-[150px]">
                    {findings.length === 0 ? (
                      <div className="flex flex-col items-center justify-center py-12 text-slate-500">
                        <History className="w-8 h-8 mb-3 opacity-50" />
                        <p className="text-sm">Aún no se han registrado hallazgos en la sesión actual.</p>
                      </div>
                    ) : (
                      <table className="w-full text-left text-sm animate-in fade-in duration-500">
                        <thead className="bg-[#0B1121] text-xs uppercase text-slate-400 border-b border-slate-700 font-semibold tracking-wider">
                          <tr>
                            <th className="px-6 py-4">ID</th>
                            <th className="px-6 py-4">Vulnerabilidad</th>
                            <th className="px-6 py-4">Vector de Ataque</th>
                            <th className="px-6 py-4">Criticidad</th>
                            <th className="px-6 py-4">Estado de Validación</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/80">
                          {findings.map((finding) => (
                            <TableRow 
                              key={finding.id}
                              id={finding.id} 
                              name={finding.name} 
                              vector={finding.vector} 
                              severity={finding.severity} 
                              status={finding.status}
                              onValidate={() => handleValidateFinding(finding.id)}
                            />
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>
              </>
            )}

            {activeTab === 'Reconocimiento (Nmap)' && <ReconView targetUrl={targetUrl} />}
            {activeTab === 'Escaneo (Nuclei/SQLMap)' && <ScanView targetUrl={targetUrl} />}
            {activeTab === 'Validación (Metasploit)' && <MetasploitView targetUrl={targetUrl} />}
            {activeTab === 'Motor Ollama IA' && <OllamaView />}
            {activeTab === 'Historial SQLite' && <HistoryView />}
            
          </div>
        </div>
      </div>
    </div>
  );
}

/* --- Componentes Auxiliares --- */

const NavItem = ({ icon, label, active, badge, onClick }: { icon: React.ReactElement, label: string, active?: boolean, badge?: string, onClick?: () => void }) => (
  <button onClick={onClick} className={`w-full flex items-center justify-between px-4 py-3 rounded-lg transition-all font-medium ${active ? 'bg-[#7A1C3E] text-white shadow-md shadow-[#7A1C3E]/20' : 'text-slate-400 hover:bg-[#7A1C3E] hover:text-white group'}`}>
    <div className="flex items-center gap-3.5">
      {React.cloneElement(icon, { className: `w-[18px] h-[18px] ${active ? 'text-white' : 'text-slate-500 group-hover:text-white'}` })}
      <span className="text-[13px] text-left">{label}</span>
    </div>
    {badge && (
      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
        active 
          ? 'bg-white/20 text-white border-white/30' 
          : 'bg-[#D4AF37]/10 text-[#D4AF37] border-[#D4AF37]/30 group-hover:bg-white/20 group-hover:text-white group-hover:border-white/30'
      }`}>
        {badge}
      </span>
    )}
  </button>
);

const MetricCard = ({ title, value, module, icon, color }: { title: string, value: string, module: string, icon: React.ReactElement, color: string }) => {
  const colorMap: Record<string, string> = {
    blue: 'text-blue-400 bg-blue-500/10 border-blue-500/20 shadow-[0_0_15px_rgba(59,130,246,0.05)]',
    indigo: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.05)]',
    red: 'text-red-400 bg-red-500/10 border-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.05)]',
    gold: 'text-[#D4AF37] bg-[#D4AF37]/10 border-[#D4AF37]/20 shadow-[0_0_15px_rgba(212,175,55,0.05)]',
  };
  
  return (
    <div className="bg-[#1E293B] border border-slate-700 rounded-xl p-6 shadow-lg transition-transform hover:-translate-y-1 duration-300">
      <div className="flex justify-between items-start">
        <div>
          <p className="text-[13px] text-slate-400 font-semibold mb-2">{title}</p>
          <h3 className="text-3xl font-black text-white tracking-tight">{value}</h3>
        </div>
        <div className={`p-3 rounded-xl border ${colorMap[color]}`}>
          {React.cloneElement(icon, { className: 'w-6 h-6' })}
        </div>
      </div>
      <div className="mt-5 pt-4 border-t border-slate-700/50 flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-widest font-bold text-slate-500">{module}</span>
      </div>
    </div>
  );
};

const TableRow = ({ id, name, vector, severity, status, onValidate }: { id: string, name: string, vector: string, severity: string, status: string, onValidate?: () => void }) => {
  const getSeverityBadge = (sev: string) => {
    switch(sev) {
      case 'Crítico': return <span className="inline-flex items-center px-2.5 py-1 rounded text-[11px] font-bold bg-red-500/10 text-red-500 border border-red-500/30 uppercase tracking-wider">CRÍTICO</span>;
      case 'Medio': return <span className="inline-flex items-center px-2.5 py-1 rounded text-[11px] font-bold bg-[#D4AF37]/10 text-[#D4AF37] border border-[#D4AF37]/30 uppercase tracking-wider">MEDIO</span>;
      case 'Info': return <span className="inline-flex items-center px-2.5 py-1 rounded text-[11px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30 uppercase tracking-wider">INFO</span>;
      default: return null;
    }
  };

  const getStatusBadge = (stat: string) => {
    switch(stat) {
      case 'checked': return (
        <div className="flex items-center gap-2 text-green-400 text-[13px] font-medium bg-green-500/5 px-3 py-1.5 rounded-lg border border-green-500/10 w-fit transition-all">
          <CheckCircle2 className="w-4 h-4" />
          <span>Metasploit Confirmed</span>
        </div>
      );
      case 'unchecked': return (
        <button onClick={onValidate} className="flex items-center gap-2 text-slate-400 hover:text-white hover:bg-slate-700 text-[13px] font-medium bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700 w-fit cursor-pointer transition-all group">
          <Clock className="w-4 h-4 group-hover:text-green-400" />
          <span>Pending Validation</span>
        </button>
      );
      case 'na': return (
        <div className="flex items-center gap-2 text-slate-500 text-[13px] font-medium px-3 py-1.5 w-fit">
          <Info className="w-4 h-4" />
          <span>N/A</span>
        </div>
      );
    }
  };

  return (
    <tr className="hover:bg-slate-800/40 transition-colors group">
      <td className="px-6 py-4 text-slate-400 font-mono text-[13px] group-hover:text-slate-300">{id}</td>
      <td className="px-6 py-4 font-semibold text-slate-200 text-[14px]">{name}</td>
      <td className="px-6 py-4 text-slate-400 font-mono text-[13px]">{vector}</td>
      <td className="px-6 py-4">{getSeverityBadge(severity)}</td>
      <td className="px-6 py-4">{getStatusBadge(status)}</td>
    </tr>
  );
};

/* --- Vistas de los Módulos Secundarios --- */

const ReconView = ({ targetUrl }: { targetUrl: string }) => (
  <div className="space-y-6 animate-in fade-in duration-300">
    <div className="grid grid-cols-3 gap-6">
      <div className="col-span-1 bg-[#1E293B] border border-slate-700 rounded-xl p-6 shadow-lg">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-blue-500/10 rounded-lg"><Network className="w-5 h-5 text-blue-400" /></div>
          <h3 className="text-white font-bold text-lg">Objetivo Activo</h3>
        </div>
        <p className="text-2xl font-mono text-blue-400 mb-1">{targetUrl}</p>
        <p className="text-slate-400 text-sm">IP Resuelta: 192.168.1.105</p>
        <div className="mt-6 pt-6 border-t border-slate-700/50">
          <div className="flex justify-between items-center mb-2">
            <span className="text-slate-400 text-sm">Estado de Red</span>
            <span className="text-green-400 text-sm font-bold flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span> ONLINE</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-slate-400 text-sm">Latencia (Ping)</span>
            <span className="text-white text-sm font-mono">12ms</span>
          </div>
        </div>
      </div>
      
      <div className="col-span-2 bg-[#1E293B] border border-slate-700 rounded-xl p-0 shadow-lg overflow-hidden flex flex-col">
        <div className="px-6 py-4 border-b border-slate-700 bg-slate-800/50 flex justify-between items-center">
          <h3 className="text-white font-bold flex items-center gap-2"><Server className="w-4 h-4 text-slate-400" /> Puertos y Servicios Descubiertos</h3>
          <button className="bg-slate-700 hover:bg-slate-600 text-xs text-white px-3 py-1.5 rounded transition-colors flex items-center gap-2">
            <Search className="w-3 h-3" /> Escanear Nuevamente
          </button>
        </div>
        <div className="flex-1 overflow-auto p-0">
          <table className="w-full text-left text-sm">
            <thead className="bg-[#0B1121] text-xs uppercase text-slate-400 border-b border-slate-700 font-semibold">
              <tr>
                <th className="px-6 py-3">Puerto</th>
                <th className="px-6 py-3">Protocolo</th>
                <th className="px-6 py-3">Servicio</th>
                <th className="px-6 py-3">Versión (Banner Grab)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              <tr className="hover:bg-slate-800/40">
                <td className="px-6 py-3 font-mono text-blue-400">80</td>
                <td className="px-6 py-3 text-slate-400">tcp</td>
                <td className="px-6 py-3 text-slate-200">http</td>
                <td className="px-6 py-3 text-slate-400 text-xs font-mono">Apache httpd 2.4.49</td>
              </tr>
              <tr className="hover:bg-slate-800/40">
                <td className="px-6 py-3 font-mono text-blue-400">443</td>
                <td className="px-6 py-3 text-slate-400">tcp</td>
                <td className="px-6 py-3 text-slate-200">https</td>
                <td className="px-6 py-3 text-slate-400 text-xs font-mono">Apache httpd 2.4.49 (OpenSSL)</td>
              </tr>
              <tr className="hover:bg-slate-800/40">
                <td className="px-6 py-3 font-mono text-blue-400">3306</td>
                <td className="px-6 py-3 text-slate-400">tcp</td>
                <td className="px-6 py-3 text-slate-200">mysql</td>
                <td className="px-6 py-3 text-slate-400 text-xs font-mono">MySQL 5.7.35-0ubuntu0.18.04.1</td>
              </tr>
              <tr className="hover:bg-slate-800/40">
                <td className="px-6 py-3 font-mono text-blue-400">8080</td>
                <td className="px-6 py-3 text-slate-400">tcp</td>
                <td className="px-6 py-3 text-slate-200">http-proxy</td>
                <td className="px-6 py-3 text-slate-400 text-xs font-mono">nginx/1.14.0</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
);

const ScanView = ({ targetUrl }: { targetUrl: string }) => (
  <div className="grid grid-cols-1 gap-6 animate-in fade-in duration-300">
    <div className="bg-[#1E293B] border border-slate-700 rounded-xl p-6 shadow-lg">
      <div className="flex justify-between items-end mb-6">
        <div>
          <h3 className="text-white font-bold text-lg flex items-center gap-2 mb-1"><ScanLine className="w-5 h-5 text-emerald-400" /> Progreso de Escaneo (Nuclei)</h3>
          <p className="text-slate-400 text-sm">Ejecutando plantillas de vulnerabilidad web, CVEs y misconfigurations en {targetUrl}.</p>
        </div>
        <div className="text-right">
          <p className="text-3xl font-black text-white">45%</p>
          <p className="text-xs text-emerald-400 font-bold uppercase tracking-widest">En Curso</p>
        </div>
      </div>
      
      <div className="w-full bg-slate-800 rounded-full h-2 mb-2 overflow-hidden border border-slate-700">
        <div className="bg-emerald-500 h-2 rounded-full relative">
          <div className="absolute top-0 right-0 bottom-0 left-0 bg-[linear-gradient(45deg,rgba(255,255,255,0.15)_25%,transparent_25%,transparent_50%,rgba(255,255,255,0.15)_50%,rgba(255,255,255,0.15)_75%,transparent_75%,transparent)] bg-[length:1rem_1rem] animate-[progress_1s_linear_infinite]"></div>
        </div>
      </div>
      
      <div className="grid grid-cols-4 gap-4 mt-8">
        <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50">
          <p className="text-xs text-slate-500 uppercase font-bold mb-1">Plantillas Cargadas</p>
          <p className="text-xl text-white font-mono">6,432</p>
        </div>
        <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50">
          <p className="text-xs text-slate-500 uppercase font-bold mb-1">Peticiones Enviadas</p>
          <p className="text-xl text-blue-400 font-mono">14,205</p>
        </div>
        <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50">
          <p className="text-xs text-slate-500 uppercase font-bold mb-1">Errores (WAF/Timeouts)</p>
          <p className="text-xl text-yellow-400 font-mono">12</p>
        </div>
        <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50">
          <p className="text-xs text-slate-500 uppercase font-bold mb-1">Hallazgos (Matches)</p>
          <p className="text-xl text-red-400 font-mono">4</p>
        </div>
      </div>
    </div>
  </div>
);

const MetasploitView = ({ targetUrl }: { targetUrl: string }) => (
  <div className="grid grid-cols-3 gap-6 h-[500px] animate-in fade-in duration-300">
    <div className="col-span-1 flex flex-col gap-6">
      <div className="bg-[#1E293B] border border-slate-700 rounded-xl p-6 shadow-lg flex-1">
        <h3 className="text-white font-bold flex items-center gap-2 mb-4"><ShieldCheck className="w-5 h-5 text-[#7A1C3E]" /> Sesiones Activas</h3>
        
        <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4 mb-4">
          <div className="flex justify-between items-start mb-2">
            <span className="text-xs text-green-400 font-bold uppercase tracking-widest">Meterpreter 1</span>
            <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
          </div>
          <p className="text-white text-sm font-mono mb-1">192.168.1.105:4444</p>
          <p className="text-slate-400 text-xs">UID: www-data (33) | OS: Linux</p>
        </div>

        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 opacity-50">
          <div className="flex justify-between items-start mb-2">
            <span className="text-xs text-slate-500 font-bold uppercase tracking-widest">Shell 2 (Muerta)</span>
            <span className="w-2 h-2 bg-red-500 rounded-full"></span>
          </div>
          <p className="text-slate-400 text-sm font-mono mb-1">192.168.1.105:4445</p>
          <p className="text-slate-500 text-xs">Conexión cerrada por el host.</p>
        </div>
      </div>
    </div>
    
    <div className="col-span-2 bg-[#000000] border border-slate-700 rounded-xl shadow-2xl flex flex-col overflow-hidden relative">
      <div className="bg-[#1E293B] px-4 py-2 border-b border-slate-700 flex items-center gap-2">
        <Terminal className="w-4 h-4 text-slate-400" />
        <span className="text-xs font-mono text-slate-300">msfconsole - {targetUrl}</span>
      </div>
      <div className="p-4 font-mono text-[13px] text-slate-300 leading-relaxed overflow-y-auto flex-1">
        <div className="text-slate-400 mb-4">
          <pre className="text-[#7A1C3E] font-bold">
{`       =[ metasploit v6.3.20-dev                          ]
+ -- --=[ 2320 exploits - 1214 auxiliary - 413 post       ]
+ -- --=[ 964 payloads - 45 encoders - 11 nops            ]`}
          </pre>
        </div>
        <div className="mb-2"><span className="text-blue-400">msf6</span> <span className="text-red-400">exploit</span>(multi/http/apache_normalize_path) {'>'} set RHOSTS 192.168.1.105</div>
        <div className="mb-2 text-slate-400">RHOSTS ={'>'} 192.168.1.105</div>
        <div className="mb-2"><span className="text-blue-400">msf6</span> <span className="text-red-400">exploit</span>(multi/http/apache_normalize_path) {'>'} exploit</div>
        <div className="mb-1 text-slate-400">[*] Started reverse TCP handler on 192.168.1.50:4444</div>
        <div className="mb-1 text-slate-400">[*] Running automatic check ("set AutoCheck false" to disable)</div>
        <div className="mb-1 text-green-400">[+] The target is vulnerable.</div>
        <div className="mb-1 text-slate-400">[*] Executing payload...</div>
        <div className="mb-1 text-green-400">[*] Meterpreter session 1 opened (192.168.1.50:4444 -{'>'} 192.168.1.105:39842) at 2026-06-06 14:04:12</div>
        <div className="mt-4 flex items-center gap-2">
          <span className="text-blue-400 border-b border-blue-400">meterpreter</span> {'>'} <span className="w-2 h-4 bg-slate-300 animate-pulse"></span>
        </div>
      </div>
    </div>
  </div>
);

const OllamaView = () => (
  <div className="flex h-[500px] border border-slate-700 rounded-xl overflow-hidden shadow-lg animate-in fade-in duration-300">
    <div className="w-64 bg-[#1E293B] border-r border-slate-700 p-4 flex flex-col">
      <button className="w-full bg-[#7A1C3E] text-white py-2 rounded-lg text-sm font-semibold flex items-center justify-center gap-2 mb-6">
        <MessageSquare className="w-4 h-4" /> Nuevo Análisis
      </button>
      <div className="text-xs text-slate-500 font-bold uppercase tracking-widest mb-3">Historial de Prompts</div>
      <div className="space-y-2 flex-1 overflow-y-auto">
        <div className="bg-slate-800 text-slate-300 text-sm p-3 rounded-lg border border-slate-600 cursor-pointer">
          <p className="truncate">Mitigación de CVE-2021-41773</p>
          <p className="text-[10px] text-slate-500 mt-1">Hace 2 min</p>
        </div>
        <div className="text-slate-400 hover:bg-slate-800 text-sm p-3 rounded-lg cursor-pointer transition-colors">
          <p className="truncate">Impacto de Inyección SQL Ciega</p>
          <p className="text-[10px] text-slate-500 mt-1">Hace 15 min</p>
        </div>
        <div className="text-slate-400 hover:bg-slate-800 text-sm p-3 rounded-lg cursor-pointer transition-colors">
          <p className="truncate">Resumen Ejecutivo del Servidor</p>
          <p className="text-[10px] text-slate-500 mt-1">Hace 1 hora</p>
        </div>
      </div>
    </div>
    <div className="flex-1 bg-[#0F172A] flex flex-col relative">
      <div className="flex-1 p-6 overflow-y-auto space-y-6">
        <div className="flex gap-4 max-w-2xl">
          <div className="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center shrink-0">
            <Lock className="w-4 h-4 text-slate-300" />
          </div>
          <div className="bg-slate-800 rounded-2xl rounded-tl-none p-4 text-sm text-slate-200">
            Explícame cómo un atacante podría abusar de la vulnerabilidad de Path Traversal en Apache (CVE-2021-41773) y dame la remediación exacta para Ubuntu.
          </div>
        </div>
        
        <div className="flex gap-4 max-w-3xl ml-auto flex-row-reverse">
          <div className="w-8 h-8 rounded-full bg-[#D4AF37]/20 flex items-center justify-center shrink-0 border border-[#D4AF37]/30">
            <Cpu className="w-4 h-4 text-[#D4AF37]" />
          </div>
          <div className="bg-[#D4AF37]/10 border border-[#D4AF37]/20 rounded-2xl rounded-tr-none p-5 text-sm text-slate-300">
            <p className="mb-3">La vulnerabilidad <strong>CVE-2021-41773</strong> ocurre en Apache HTTP Server 2.4.49. Se introdujo un fallo en la normalización de rutas que permite a un atacante usar secuencias de tipo <code className="bg-black/50 text-[#D4AF37] px-1 rounded">.%2e/</code> para escapar del directorio raíz del servidor web.</p>
            <p className="mb-4">Si los archivos fuera del DocumentRoot no están protegidos por una directiva "require all denied", el atacante puede leer archivos sensibles como <code className="bg-black/50 text-red-400 px-1 rounded">/etc/passwd</code>. Si CGI está habilitado, puede llevar a <strong>Ejecución Remota de Código (RCE)</strong>.</p>
            
            <h5 className="font-bold text-[#D4AF37] mb-2 uppercase text-xs tracking-wider">Comandos de Remediación (Ubuntu):</h5>
            <div className="bg-black/60 p-3 rounded-lg border border-slate-700 font-mono text-[13px] text-green-400 space-y-1">
              <p># 1. Actualizar repositorios</p>
              <p className="text-slate-300">sudo apt update</p>
              <p># 2. Instalar la versión parcheada de Apache2</p>
              <p className="text-slate-300">sudo apt install --only-upgrade apache2</p>
              <p># 3. Reiniciar el servicio</p>
              <p className="text-slate-300">sudo systemctl restart apache2</p>
            </div>
          </div>
        </div>
      </div>
      
      <div className="p-4 border-t border-slate-800 bg-[#1E293B]">
        <div className="relative">
          <input 
            type="text" 
            placeholder="Pregunta a Llama 3 sobre vulnerabilidades o mitigación..." 
            className="w-full bg-[#0B1121] border border-slate-700 rounded-lg pl-4 pr-12 py-3 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-[#D4AF37]/50 focus:ring-1 focus:ring-[#D4AF37]/50"
            readOnly
          />
          <button className="absolute right-2 top-2 bottom-2 bg-[#D4AF37] hover:bg-[#B3932E] text-[#0B1121] p-2 rounded-md transition-colors">
            <Play className="w-4 h-4 fill-current" />
          </button>
        </div>
      </div>
    </div>
  </div>
);

const HistoryView = () => (
  <div className="bg-[#1E293B] border border-slate-700 rounded-xl overflow-hidden shadow-lg animate-in fade-in duration-300">
    <div className="px-6 py-5 border-b border-slate-700 bg-slate-800/50 flex justify-between items-center">
      <h3 className="font-bold text-white flex items-center gap-2"><History className="w-5 h-5 text-slate-400" /> Registro de Auditorías Anteriores</h3>
      <div className="relative">
        <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
        <input 
          type="text" 
          placeholder="Buscar target o fecha..." 
          className="bg-[#0B1121] border border-slate-700 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-300 placeholder-slate-500 focus:outline-none"
        />
      </div>
    </div>
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="bg-[#0B1121] text-xs uppercase text-slate-400 border-b border-slate-700 font-semibold tracking-wider">
          <tr>
            <th className="px-6 py-4">Fecha</th>
            <th className="px-6 py-4">Objetivo Escaneado</th>
            <th className="px-6 py-4">Duración</th>
            <th className="px-6 py-4 text-center">Críticas</th>
            <th className="px-6 py-4">Estado</th>
            <th className="px-6 py-4">Reporte</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/80">
          <tr className="hover:bg-slate-800/40">
            <td className="px-6 py-4 text-slate-400"><div className="flex items-center gap-2"><Calendar className="w-3 h-3" /> 06 Jun, 2026</div></td>
            <td className="px-6 py-4 text-white font-mono">corp.internal.uide.edu.ec</td>
            <td className="px-6 py-4 text-slate-400">12m 45s</td>
            <td className="px-6 py-4 text-center"><span className="bg-red-500/20 text-red-400 px-2 py-1 rounded font-bold">2</span></td>
            <td className="px-6 py-4"><span className="text-green-400 flex items-center gap-1"><CheckCircle2 className="w-4 h-4" /> Completado</span></td>
            <td className="px-6 py-4"><button className="text-[#D4AF37] hover:text-white hover:underline flex items-center gap-1"><FileText className="w-3 h-3" /> PDF</button></td>
          </tr>
          <tr className="hover:bg-slate-800/40">
            <td className="px-6 py-4 text-slate-400"><div className="flex items-center gap-2"><Calendar className="w-3 h-3" /> 04 Jun, 2026</div></td>
            <td className="px-6 py-4 text-white font-mono">vpn.uide.edu.ec</td>
            <td className="px-6 py-4 text-slate-400">08m 12s</td>
            <td className="px-6 py-4 text-center"><span className="bg-slate-700 text-slate-400 px-2 py-1 rounded font-bold">0</span></td>
            <td className="px-6 py-4"><span className="text-green-400 flex items-center gap-1"><CheckCircle2 className="w-4 h-4" /> Completado</span></td>
            <td className="px-6 py-4"><button className="text-[#D4AF37] hover:text-white hover:underline flex items-center gap-1"><FileText className="w-3 h-3" /> PDF</button></td>
          </tr>
          <tr className="hover:bg-slate-800/40">
            <td className="px-6 py-4 text-slate-400"><div className="flex items-center gap-2"><Calendar className="w-3 h-3" /> 29 May, 2026</div></td>
            <td className="px-6 py-4 text-white font-mono">api.gateway.local</td>
            <td className="px-6 py-4 text-slate-400">04m 30s</td>
            <td className="px-6 py-4 text-center">-</td>
            <td className="px-6 py-4"><span className="text-red-400 flex items-center gap-1"><AlertTriangle className="w-4 h-4" /> Error (WAF Block)</span></td>
            <td className="px-6 py-4"><span className="text-slate-600">N/A</span></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
);
