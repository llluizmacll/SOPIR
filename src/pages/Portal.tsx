import { useMemo } from 'react';
import { securityScore, useStore } from '../lib/store';
import { download, toCSV } from '../lib/store';
import { AreaChart, Gauge, Spark } from '../components/charts';
import { Icon, Panel, Pill } from '../components/ui';

export default function Portal() {
  const { s, scope, tenantName, toast } = useStore();

  const alerts = useMemo(() => scope(s.alerts), [s.alerts, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps
  const incidents = useMemo(() => scope(s.incidents), [s.incidents, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps
  const vulns = useMemo(() => scope(s.vulns), [s.vulns, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps
  const assets = useMemo(() => scope(s.assets), [s.assets, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps

  const { score } = useMemo(() => securityScore({ alerts, incidents, vulns, assets }), [alerts, incidents, vulns, assets]);

  const activeInc = incidents.filter(i => !['resolvido', 'fechado'].includes(i.status));
  const critVulns = vulns.filter(v => v.severity === 'critical' && !['resolvida', 'aceita'].includes(v.status));
  const slaOk = incidents.length ? Math.round((incidents.filter(i => ['resolvido', 'fechado'].includes(i.status)).length / incidents.length) * 100) : 100;

  const trend = useMemo(() => Array.from({ length: 30 }, (_, i) => {
    const wobble = Math.sin(i / 3.1) * 3 + Math.cos(i / 1.7) * 2;
    return Math.round(Math.max(40, Math.min(97, score - 9 + (i / 30) * 9 + wobble)));
  }), [score]);

  const recommendations = [
    ...critVulns.slice(0, 3).map(v => ({
      tag: 'Vulnerabilidade', color: '#ff4d5e',
      text: `Correção prioritária identificada em ${v.asset}. Nossa equipe já possui plano de patch e janela proposta.`,
    })),
    ...activeInc.slice(0, 2).map(i => ({
      tag: 'Evento em tratamento', color: '#ff9142',
      text: `Evento de severidade ${i.severity === 'critical' ? 'crítica' : 'alta'} em contenção pela equipe — atualizações no relatório diário.`,
    })),
    { tag: 'Boas práticas', color: '#2fd6a5', text: 'Revisão trimestral de acessos privilegiados recomendada para reduzir superfície de ataque.' },
    { tag: 'Monitoramento', color: '#56c4ff', text: 'Cobertura de agentes em ' + Math.round((assets.filter(a => a.status === 'online').length / Math.max(1, assets.length)) * 100) + '% dos ativos — dentro da meta contratada.' },
  ];

  const stats = [
    { label: 'Ativos monitorados', value: assets.length.toLocaleString('pt-BR'), icon: 'server', color: '#56c4ff', sub: `${assets.filter(a => a.status === 'online').length} com agente ativo` },
    { label: 'Eventos em tratamento', value: String(activeInc.length), icon: 'shieldCheck', color: activeInc.some(i => i.severity === 'critical') ? '#ff9142' : '#2fd6a5', sub: activeInc.length ? 'equipe dedicada atuando' : 'ambiente estável' },
    { label: 'Correções prioritárias', value: String(critVulns.length), icon: 'bug', color: critVulns.length ? '#ff4d5e' : '#2fd6a5', sub: `${vulns.filter(v => v.status === 'resolvida').length} já resolvidas` },
    { label: 'SLA contratual', value: `${slaOk}%`, icon: 'clock', color: slaOk >= 95 ? '#2fd6a5' : '#ffc53d', sub: 'tempo de resposta e resolução' },
  ];

  const exportReport = () => {
    download('sopir-postura-seguranca.csv', toCSV([
      { indicador: 'Security Score', valor: score },
      { indicador: 'Ativos monitorados', valor: assets.length },
      { indicador: 'Eventos em tratamento', valor: activeInc.length },
      { indicador: 'Correções prioritárias abertas', valor: critVulns.length },
      { indicador: 'Vulnerabilidades resolvidas', valor: vulns.filter(v => v.status === 'resolvida').length },
      { indicador: 'SLA (%)', valor: slaOk },
    ]), 'text/csv');
    toast('ok', 'Relatório de postura exportado (CSV)');
  };

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-[1200px] p-6">
        {/* cabeçalho do cliente */}
        <div className="a-up flex flex-wrap items-end justify-between gap-3">
          <div>
            <div className="lbl mb-1">visão executiva do ambiente</div>
            <h2 className="font-display text-[24px] font-bold tracking-tight text-ink">{tenantName}</h2>
            <p className="mt-1 max-w-[560px] text-[12.5px] text-faint">
              Acompanhe como está a segurança do seu ambiente — sem jargão técnico. Detalhes operacionais ficam com o nosso SOC.
            </p>
          </div>
          <div className="flex gap-2">
            <button className="btn" onClick={() => toast('info', 'Relatório mensal em PDF será enviado por e-mail')}>
              <Icon name="file" size={13} /> Relatório mensal (PDF)
            </button>
            <button className="btn btn-primary" onClick={exportReport}>
              <Icon name="download" size={13} /> Exportar postura (CSV)
            </button>
          </div>
        </div>

        {/* score + stats */}
        <div className="mt-5 grid grid-cols-12 gap-4">
          <div className="panel a-up col-span-12 flex flex-col items-center gap-2 p-6 md:col-span-4" style={{ animationDelay: '60ms' }}>
            <Gauge value={score} size={212} />
            <div className="text-center">
              <div className="font-display text-[15px] font-semibold text-ink">Security Score</div>
              <div className="mt-1 flex items-center justify-center gap-2 text-[12px]">
                <span className="flex items-center gap-1 text-teal"><Icon name="arrowUpRight" size={12} /> melhorando</span>
                <span className="text-faint">· +9 pts nos últimos 30 dias</span>
              </div>
            </div>
            <div className="mt-2 w-full border-t border-line pt-3">
              <div className="lbl mb-2">Evolução 30 dias</div>
              <Spark data={trend} color="#2fd6a5" w={230} h={38} />
            </div>
          </div>

          <div className="col-span-12 grid grid-cols-1 gap-4 sm:grid-cols-2 md:col-span-8">
            {stats.map((st, i) => (
              <div key={st.label} className="panel a-up flex flex-col justify-between p-5" style={{ animationDelay: `${100 + i * 60}ms` }}>
                <div className="flex items-center justify-between">
                  <span className="lbl">{st.label}</span>
                  <span style={{ color: st.color + 'aa' }}><Icon name={st.icon} size={16} /></span>
                </div>
                <div className="mt-3 font-mono text-[32px] font-bold leading-none tabular-nums" style={{ color: st.color }}>{st.value}</div>
                <div className="mt-2 text-[11.5px] text-faint">{st.sub}</div>
              </div>
            ))}
          </div>
        </div>

        {/* tendência + recomendações */}
        <div className="mt-4 grid grid-cols-12 gap-4">
          <Panel title="Tendência da postura de segurança" icon="activity" className="col-span-12 xl:col-span-7" delay={120}
            right={<Pill label="últimos 30 dias" color="#56c4ff" sm />}>
            <AreaChart data={trend} height={180} unit="pts" />
          </Panel>

          <Panel title="Riscos & recomendações" icon="target" className="col-span-12 xl:col-span-5" delay={180}>
            <div className="flex flex-col gap-2.5">
              {recommendations.map((r, i) => (
                <div key={i} className="a-up flex gap-3 rounded-lg border border-line/70 bg-panel px-3.5 py-3" style={{ animationDelay: `${200 + i * 60}ms` }}>
                  <span className="mt-0.5 shrink-0" style={{ color: r.color }}><Icon name="flag" size={13} /></span>
                  <div>
                    <span className="mr-2 rounded px-1.5 py-0.5 text-[9.5px] font-semibold uppercase tracking-wider"
                      style={{ color: r.color, background: r.color + '18', border: `1px solid ${r.color}40` }}>{r.tag}</span>
                    <p className="mt-1 text-[12px] leading-relaxed text-sub">{r.text}</p>
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        </div>

        {/* como funciona */}
        <div className="a-up mt-4 rounded-xl border border-line bg-panel/60 p-5" style={{ animationDelay: '240ms' }}>
          <div className="lbl mb-3">Como o SOPIR protege o seu ambiente</div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {[
              { icon: 'radar', title: 'Detectar', text: 'Sensores e SIEM integrados monitoram o ambiente 24/7 e convertem ruído em alertas relevantes.' },
              { icon: 'crosshair', title: 'Investigar & Responder', text: 'Nossa equipe investiga, contém ameaças e executa respostas com aprovação registrada.' },
              { icon: 'shieldCheck', title: 'Remediar & Melhorar', text: 'Vulnerabilidades são corrigidas e validadas; o Security Score acompanha a evolução.' },
            ].map((c, i) => (
              <div key={c.title} className="a-up rounded-lg border border-line/70 bg-panel p-4" style={{ animationDelay: `${280 + i * 70}ms` }}>
                <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-teal/40 bg-teal/10 text-teal">
                  <Icon name={c.icon} size={15} />
                </span>
                <div className="mt-2.5 font-display text-[13.5px] font-semibold text-ink">{c.title}</div>
                <p className="mt-1 text-[11.5px] leading-relaxed text-faint">{c.text}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="mt-4 pb-2 text-center font-mono text-[10px] text-faint">
          SOPIR Customer Portal · dados isolados por tenant · atualizado em tempo real
        </div>
      </div>
    </div>
  );
}
