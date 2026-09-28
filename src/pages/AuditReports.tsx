import { SEED_REPORTS } from '../data/mock';
import { can, download, toCSV, timeAgo, useStore } from '../lib/store';
import { Icon, Pill } from '../components/ui';

// ── Relatórios ───────────────────────────────────────────────
export function ReportsPage() {
  const { s, scope, toast } = useStore();

  const templates = [
    { id: 't1', name: 'Relatório mensal de segurança', desc: 'Resumo executivo, incidentes, alertas, vulnerabilidades, SLA e recomendações.', icon: 'file' },
    { id: 't2', name: 'Resumo de incidentes', desc: 'Incidentes do período com timeline, severidade, SLA e status de resolução.', icon: 'flame' },
    { id: 't3', name: 'Vulnerabilidades & correções', desc: 'Findings abertos e resolvidos, CVSS, risco por ativo e tempo de correção.', icon: 'bug' },
    { id: 't4', name: 'Postura do cliente', desc: 'Security Score, tendências e recomendações em linguagem executiva.', icon: 'globe' },
  ];

  const buildPayload = () => ({
    gerado_em: new Date().toISOString(),
    tenant: s.tenant,
    incidentes: scope(s.incidents).map(i => ({ id: i.id, titulo: i.title, severidade: i.severity, status: i.status, sla_h: i.slaH })),
    alertas: scope(s.alerts).map(a => ({ id: a.id, titulo: a.title, severidade: a.severity, status: a.status })),
    vulnerabilidades: scope(s.vulns).map(v => ({ cve: v.cve, cvss: v.cvss, ativo: v.asset, status: v.status })),
  });

  const generate = (name: string, format: string) => {
    if (format === 'PDF') {
      toast('info', `"${name}" em PDF entrou na fila de geração — envio por e-mail em instantes`);
      return;
    }
    const payload = buildPayload();
    if (format === 'JSON') {
      download(`sopir-${name.toLowerCase().replace(/\s+/g, '-')}.json`, JSON.stringify(payload, null, 2));
    } else {
      download(`sopir-${name.toLowerCase().replace(/\s+/g, '-')}.csv`, toCSV(
        payload.incidentes.map(i => ({ tipo: 'incidente', id: i.id, titulo: i.titulo, severidade: i.severidade, status: i.status })),
      ), 'text/csv');
    }
    toast('ok', `"${name}" exportado em ${format}`);
  };

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-[1100px] p-5">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {templates.map((t, i) => (
            <div key={t.id} className="panel a-up p-5" style={{ animationDelay: `${i * 60}ms` }}>
              <div className="flex items-center gap-3">
                <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-teal/35 bg-teal/10 text-teal">
                  <Icon name={t.icon} size={16} />
                </span>
                <div>
                  <div className="font-display text-[14px] font-semibold text-ink">{t.name}</div>
                  <div className="lbl mt-0.5">escopo: tenant atual</div>
                </div>
              </div>
              <p className="mt-3 text-[12px] leading-relaxed text-faint">{t.desc}</p>
              <div className="mt-4 flex flex-wrap gap-2">
                {['PDF', 'CSV', 'JSON'].map(f => (
                  <button key={f} className={`btn btn-xs ${f === 'PDF' ? 'btn-primary' : ''}`} onClick={() => generate(t.name, f)}
                    disabled={f !== 'PDF' && !can(s.role, 'reports.export')}>
                    <Icon name={f === 'PDF' ? 'file' : 'download'} size={12} /> {f}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="panel a-up mt-4" style={{ animationDelay: '260ms' }}>
          <div className="panel-hd">
            <Icon name="history" size={14} className="text-teal" />
            <h3 className="font-display text-[11.5px] font-semibold uppercase tracking-[0.14em]">Gerados anteriormente</h3>
          </div>
          {SEED_REPORTS.map(r => (
            <div key={r.id} className="flex items-center gap-3 border-t border-line/60 px-4 py-2.5 first:border-t-0">
              <Icon name="file" size={14} className="shrink-0 text-sub" />
              <div className="min-w-0">
                <div className="truncate text-[12.5px] text-ink/90">{r.name}</div>
                <div className="font-mono text-[10px] text-faint">{r.period} · por {r.by} · {timeAgo(r.ts)}</div>
              </div>
              <span className="ml-auto"><Pill label={r.format} color="#56c4ff" sm /></span>
              <button className="btn btn-ghost btn-xs" onClick={() => toast('info', `Download de "${r.name}" iniciado`)}>
                <Icon name="download" size={13} />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
