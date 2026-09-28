import { useEffect, useMemo, useRef, useState } from 'react';
import { SEV_META } from '../data/mock';
import { can, timeAgo, useStore } from '../lib/store';
import { EmptyState, Icon, Pill, SevBadge } from '../components/ui';

const RUN_META: Record<string, { label: string; color: string }> = {
  andamento: { label: 'Em execução', color: '#56c4ff' },
  aprovacao: { label: 'Aguardando aprovação', color: '#ffc53d' },
  concluido: { label: 'Concluído', color: '#2fd6a5' },
  rejeitado: { label: 'Rejeitado', color: '#ff4d5e' },
};

export default function Playbooks() {
  const { s, scope, nav, startRun, tickRun, approveRun, rejectRun, toast } = useStore();
  const [selectedId, setSelectedId] = useState<string>(s.playbooks[0]?.id ?? 'PB-RANSOM');

  useEffect(() => {
    if (s.focus?.type === 'pb') { setSelectedId(s.focus.id); nav('playbooks', null); }
  }, [s.focus, nav]);

  // motor da execução: avança um passo por vez
  useEffect(() => {
    const run = s.runs.find(r => r.status === 'andamento');
    if (!run) return;
    const t = setTimeout(() => tickRun(run.id), 1150);
    return () => clearTimeout(t);
  }, [s.runs, tickRun]);

  // avisos de conclusão/rejeição
  const toasted = useRef<Set<string>>(new Set());
  useEffect(() => {
    s.runs.forEach(r => {
      if ((r.status === 'concluido' || r.status === 'rejeitado') && !toasted.current.has(r.id)) {
        toasted.current.add(r.id);
        if (r.status === 'concluido') toast('ok', `Playbook "${r.pbName}" concluído — passos registrados em auditoria`);
        else toast('err', `Execução de "${r.pbName}" abortada após rejeição`);
      }
    });
  }, [s.runs, toast]);

  const pb = s.playbooks.find(p => p.id === selectedId) ?? s.playbooks[0];
  const runs = useMemo(() => scope(s.runs), [s.runs, s.tenant]); // eslint-disable-line react-hooks/exhaustive-deps
  const activeRun = runs.find(r => r.pbId === pb?.id && (r.status === 'andamento' || r.status === 'aprovacao')) ?? null;

  const canExecute = can(s.role, 'response.execute');
  const canApprove = can(s.role, 'response.approve');

  if (!pb) return <EmptyState icon="zap" title="Nenhum playbook disponível" />;

  return (
    <div className="flex h-full">
      {/* lista de playbooks */}
      <div className="a-up flex w-[330px] shrink-0 flex-col border-r border-line bg-panel/30">
        <div className="border-b border-line px-4 py-3">
          <div className="lbl">Biblioteca de resposta</div>
          <div className="mt-0.5 font-mono text-[10.5px] text-faint">{s.playbooks.length} playbooks · aprovação obrigatória p/ ações de rede</div>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-2.5">
          {s.playbooks.map(p => {
            const lastRun = runs.find(r => r.pbId === p.id);
            return (
              <button key={p.id} onClick={() => setSelectedId(p.id)}
                className={`mb-2 w-full rounded-lg border p-3.5 text-left transition-all ${selectedId === p.id ? 'border-teal/50 bg-teal/[.06]' : 'border-line bg-panel hover:border-line2'}`}>
                <div className="flex items-center gap-2">
                  <span className="flex h-7 w-7 items-center justify-center rounded-md border border-line bg-panel2 text-teal"><Icon name="zap" size={13} /></span>
                  <span className="font-display text-[13px] font-semibold text-ink">{p.name}</span>
                  <span className="ml-auto"><SevBadge sev={p.severity} sm /></span>
                </div>
                <div className="mt-2 font-mono text-[10px] text-faint">gatilho: {p.trigger}</div>
                <div className="mt-2 flex items-center gap-2">
                  <span className="font-mono text-[10px] text-sub">{p.steps.length} passos · {p.steps.filter(st => st.approval).length} com aprovação</span>
                  {lastRun && <span className="ml-auto"><Pill label={RUN_META[lastRun.status].label} color={RUN_META[lastRun.status].color} sm /></span>}
                </div>
              </button>
            );
          })}

          <div className="lbl mt-4 mb-2 px-1">Histórico de execuções</div>
          {runs.length === 0 && <div className="px-1 text-[11px] text-faint">Nenhuma execução neste escopo ainda.</div>}
          {runs.map(r => (
            <div key={r.id} className="mb-1.5 rounded-lg border border-line/70 bg-panel px-3 py-2">
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10px] text-teal">{r.id}</span>
                <span className="truncate text-[11.5px] text-ink/85">{r.pbName}</span>
                <span className="ml-auto"><Pill label={RUN_META[r.status].label} color={RUN_META[r.status].color} sm /></span>
              </div>
              <div className="mt-1 font-mono text-[9.5px] text-faint">{r.actor} · {timeAgo(r.ts)}</div>
            </div>
          ))}
        </div>
      </div>

      {/* detalhe / runner */}
      <div className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-[860px] p-5">
          <div className="panel a-up p-5">
            <div className="flex flex-wrap items-start gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="font-mono text-[12px] text-teal">{pb.id}</span>
                  <SevBadge sev={pb.severity} />
                  <span className="font-mono text-[10px] text-faint">SOAR · resposta orquestrada</span>
                </div>
                <h2 className="mt-1.5 font-display text-[19px] font-bold text-ink">{pb.name}</h2>
                <p className="mt-1 text-[12px] text-faint">Gatilho: <span className="text-sub">{pb.trigger}</span></p>
              </div>
              <button className="btn btn-primary" disabled={!canExecute || !!activeRun}
                title={canExecute ? undefined : 'requer permissão response.execute'}
                onClick={() => startRun(pb.id)}>
                <Icon name="play" size={14} /> {activeRun ? 'Execução em curso…' : 'Executar playbook'}
              </button>
            </div>
            {!canExecute && (
              <div className="mt-3 flex items-center gap-1.5 rounded-md border border-line bg-panel px-3 py-2 text-[11px] text-faint">
                <Icon name="lock" size={11} /> Seu perfil atual não possui <span className="font-mono text-sub">response.execute</span> — troque para Admin/Manager para testar.
              </div>
            )}
          </div>

          {/* pipeline */}
          <div className="panel a-up mt-4 p-5" style={{ animationDelay: '90ms' }}>
            <div className="lbl mb-4 flex items-center gap-2">
              <Icon name="layers" size={12} /> Pipeline de execução
              {activeRun && <span className="ml-2 font-mono text-[10px] text-cyan">passo {Math.min(activeRun.step + 1, pb.steps.length)}/{pb.steps.length}</span>}
            </div>
            <div className="relative ml-3 flex flex-col">
              {pb.steps.map((step, i) => {
                const state: 'done' | 'now' | 'wait' | 'todo' = !activeRun
                  ? 'todo'
                  : i < activeRun.step ? 'done'
                  : i === activeRun.step ? (activeRun.status === 'aprovacao' ? 'wait' : 'now')
                  : activeRun.status === 'aprovacao' || activeRun.status === 'andamento' ? 'todo' : 'todo';
                const last = i === pb.steps.length - 1;
                return (
                  <div key={step.id} className="relative flex gap-4 pb-5 last:pb-0">
                    {!last && (
                      <span className="absolute left-[13px] top-8 bottom-0 w-px">
                        <svg className="h-full w-full" preserveAspectRatio="none" viewBox="0 0 2 100">
                          <line x1="1" y1="0" x2="2" y2="100" stroke={state === 'done' ? '#2fd6a5' : 'var(--color-line2)'} strokeWidth="2"
                            className={state === 'now' ? 'dashline' : ''} vectorEffect="non-scaling-stroke" />
                        </svg>
                      </span>
                    )}
                    <span className={`z-10 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border-2 transition-colors ${
                      state === 'done' ? 'border-teal bg-teal text-[#04160f]'
                      : state === 'now' ? 'border-cyan bg-cyan/15 text-cyan'
                      : state === 'wait' ? 'border-med bg-med/15 text-med'
                      : 'border-line2 bg-panel2 text-faint'}`}>
                      {state === 'done' ? <Icon name="check" size={12} strokeWidth={2.6} />
                        : state === 'now' ? <span className="h-2 w-2 animate-pulse rounded-full bg-cyan" />
                        : state === 'wait' ? <Icon name="lock" size={11} />
                        : <span className="font-mono text-[10px]">{i + 1}</span>}
                    </span>
                    <div className={`min-w-0 flex-1 rounded-lg border px-4 py-3 transition-colors ${
                      state === 'wait' ? 'border-med/50 bg-med/[.07]' : state === 'now' ? 'border-cyan/40 bg-cyan/[.05]' : state === 'done' ? 'border-teal/25 bg-panel' : 'border-line bg-panel'}`}>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`text-[13px] font-medium ${state === 'todo' ? 'text-sub' : 'text-ink'}`}>{step.label}</span>
                        {step.approval && <Pill label="requer aprovação" color="#ffc53d" sm />}
                        {step.effect?.isolate && <Pill label={`isola ${step.effect.isolate}`} color="#ff9142" sm />}
                        {step.effect?.block && <Pill label={`bloqueia ${step.effect.block}`} color="#ff9142" sm />}
                        {state === 'now' && <span className="ml-auto font-mono text-[10px] text-cyan">executando…</span>}
                        {state === 'done' && <span className="ml-auto font-mono text-[10px] text-teal">concluído</span>}
                      </div>
                      {step.desc && <div className="mt-0.5 text-[11.5px] text-faint">{step.desc}</div>}
                      {state === 'wait' && (
                        <div className="a-pop mt-3 flex flex-wrap items-center gap-2 rounded-md border border-med/40 bg-input-bg px-3 py-2.5">
                          <span className="text-[11.5px] text-med">Autorização necessária antes de executar esta ação.</span>
                          <div className="ml-auto flex gap-2">
                            <button className="btn btn-primary btn-xs" disabled={!canApprove}
                              title={canApprove ? undefined : 'requer permissão response.approve'}
                              onClick={() => approveRun(activeRun!.id)}>
                              <Icon name="check" size={12} /> Aprovar
                            </button>
                            <button className="btn btn-danger btn-xs" disabled={!canApprove} onClick={() => rejectRun(activeRun!.id)}>
                              <Icon name="x" size={12} /> Rejeitar
                            </button>
                          </div>
                          {!canApprove && <span className="w-full text-[10px] text-faint"><Icon name="lock" size={9} className="mr-1 inline" />seu perfil não possui response.approve</span>}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* governança */}
          <div className="panel a-up mt-4 p-5" style={{ animationDelay: '160ms' }}>
            <div className="lbl mb-3">Modelo de governança da Response Engine</div>
            <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10.5px]">
              {['Solicitação', 'Autorização', 'Política', 'Aprovação?', 'Executar', 'Validar', 'Audit'].map((st, i, arr) => (
                <span key={st} className="flex items-center gap-1.5">
                  <span className={`rounded border px-2 py-1 ${st === 'Aprovação?' ? 'border-med/50 text-med' : st === 'Audit' ? 'border-teal/50 text-teal' : 'border-line text-sub'}`}>{st}</span>
                  {i < arr.length - 1 && <Icon name="chevronRight" size={11} className="text-faint" />}
                </span>
              ))}
            </div>
            <p className="mt-3 max-w-[640px] text-[12px] leading-relaxed text-faint">
              Toda ação de resposta passa por política e trilha de auditoria. Ações com impacto de rede
              (isolamento, bloqueio de IP/domínio) param em aprovação humana — o executor nunca age sem autorização registrada.
              <button className="ml-1.5 text-teal hover:underline" onClick={() => nav('audit')}>ver auditoria →</button>
            </p>
          </div>

          {/* efeitos observáveis */}
          <div className="a-up mt-4 flex flex-wrap items-center gap-x-5 gap-y-1 rounded-lg border border-line/60 bg-panel/50 px-4 py-2.5 font-mono text-[10.5px] text-faint" style={{ animationDelay: '220ms' }}>
            <span className="text-teal">● efeitos cruzados:</span>
            <span>isolamento reflete em Ativos</span>
            <span>bloqueio gera regra no FW-MATRIZ</span>
            <span>cada passo grava em Auditoria</span>
            <span className="ml-auto" style={{ color: SEV_META[pb.severity].color }}>severidade do gatilho: {SEV_META[pb.severity].label}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
