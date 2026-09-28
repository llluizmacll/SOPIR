# SOPIR — Security Operations & Incident Response Platform

Plataforma que unifica **detecção → investigação → resposta → remediação → visão do cliente**
em um único lugar. Não é "uma interface melhor para o Wazuh": é a camada operacional
do SOC, multi-tenant, com connectors normalizados e resposta orquestrada.

```
                    ┌──────────────────────────┐
                    │          SOPIR           │
                    └────────────┬─────────────┘
        ┌────────────────────────┼────────────────────────┐
     DETECTAR               INVESTIGAR                 PROTEGER
   Wazuh · FortiSIEM      Incidents · Cases        Playbooks · SOAR
   (connectors reais)     IOCs · Evidências        Aprovação · Audit
        └──────────────┬─────┴──────┬─────────────────────┘
                   REMEDIAR      VISUALIZAR
               Vulns · Patches   Dashboards · Relatórios
               Validação         Security Score · Portal
```

## Stack

| Camada | Tecnologia |
|---|---|
| Frontend | React 18 + Vite + Tailwind v4 (SPA, modo demo embutido) |
| Backend | `sopir-api` — Node 20 (ESM) + Express |
| Banco | PostgreSQL 16 (migrações idempotentes no boot) |
| Connectors | Wazuh Indexer (OpenSearch) · Wazuh Manager API · FortiSIEM REST · Webhook push |
| Infra | Docker Compose + nginx (SPA + proxy de API) |

## Quickstart

```bash
docker compose up -d --build
```

- **Plataforma:** http://localhost:8080
- **API:** http://localhost:3000/api/v1 (`/health`, `/bootstrap`, `/events`, …)
- Sem connectors configurados, o **simulador** gera fluxo de demonstração
  passando pelo mesmo pipeline de normalização dos connectors reais.

Sem Docker, o frontend roda standalone em **modo demonstração**
(`npm run dev`): dados locais, fluxo simulado, todas as features ativas.
Quando a `sopir-api` responde, o frontend hidrata do banco e passa a
persistir toda ação via REST — o indicador no topo mostra
`sopir-api · PostgreSQL` (verde) ou `modo demonstração` (âmbar).

## Conectar ferramentas reais

```env
# Wazuh (recomendado via Indexer)
WAZUH_INDEXER_URL=https://wazuh-indexer:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=<senha>

# FortiSIEM — REST ou push:
# POST /api/v1/ingest  (X-Api-Key) a partir das regras de notificação
```

Detalhes em [`backend/README.md`](backend/README.md).

## Módulos

1. **Centro de Operações** — Security Score dinâmico, fluxo ao vivo, SLA sob risco, conectores
2. **Event Explorer** — busca sobre o modelo normalizado + evento original + relacionados
3. **Central de Alertas** — triagem, classificação, atribuição, escalonamento
4. **Incident Response** — severidade/SLA (4h–72h), timeline, tarefas, IOCs
5. **Case Management** — Kanban com a árvore completa do caso
6. **Response Engine / SOAR** — playbooks com aprovação humana e efeitos reais (isolamento, bloqueio)
7. **Vulnerability Management** — CVE/CVSS × criticidade do ativo, remediação
8. **Asset Management** — inventário correlacionado + contenção de endpoint
9. **Portal do Cliente** — Security Score e recomendações sem jargão
10. **Relatórios & Auditoria** — exportação real (CSV/JSON) e trilha imutável

Cross-cutting: **multi-tenant** (3 clientes isolados + visão MSSP) e
**RBAC** (Admin, SOC Manager, SOC Analyst, Security Engineer, Customer).

## Roadmap

- [x] Fase 1 — frontend operacional completo
- [x] Fase 2 — backend, persistência PostgreSQL e connectors reais
- [ ] Fase 3 — autenticação JWT + RBAC server-side, motor de correlação por política
- [ ] Fase 4 — Investigation Graph (IP → usuário → endpoint → processo → IOC)
