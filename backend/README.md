# SOPIR API

Backend da plataforma **SOPIR — Security Operations & Incident Response**:
persistência em PostgreSQL, collectors reais (Wazuh / FortiSIEM), pipeline de
normalização, Response Engine com aprovação e auditoria completa.

## Arquitetura

```
 Wazuh Indexer ─┐                     ┌─→ events (normalizado)
 Wazuh Manager ─┼─→ connectors ─→ ingest ─→ alerts (auto, dedup 15min)
 FortiSIEM ─────┤    (poll+cursor)     └─→ connector_state (checkpoint)
 Webhook push ──┘
                                                    ┌→ incidents/cases
 API REST /api/v1 ──────────────────────────────── ┤→ playbook_runs (engine)
                                                    └→ audit (trilha)
```

## Rodando

Via compose (recomendado, a partir da raiz do projeto):

```bash
docker compose up -d --build
curl http://localhost:3000/api/v1/health
```

Localmente (sem Docker):

```bash
cd backend
npm install
export DATABASE_URL=postgres://sopir:sopir@localhost:5432/sopir
npm run dev
```

No primeiro boot: migrações idempotentes + baseline de demonstração
(somente se o banco estiver vazio). Sem connectors configurados, o
**simulador** gera fluxo contínuo pelo mesmo pipeline de normalização
(`SOPIR_SIMULATE=auto|true|false`).

## Connectors

### Wazuh — modo Wazuh Indexer (recomendado)

```env
WAZUH_INDEXER_URL=https://wazuh-indexer:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=<senha>
WAZUH_INDEX_PATTERN=wazuh-alerts-4.x-*
WAZUH_TENANT=vetra
```

Coleta incremental com cursor de timestamp persistido em `connector_state`.

### Wazuh — modo Manager API (4.8+)

```env
WAZUH_MANAGER_URL=https://wazuh-manager:55000
WAZUH_API_USER=api-user
WAZUH_API_PASS=<senha>
```

### FortiSIEM

O Phoenix REST varia por versão. O connector tenta login + endpoints
conhecidos e reporta erro claro se a versão não expuser eventos.
A integração recomendada é **push** (abaixo).

### Push / Webhook (qualquer fonte)

```bash
curl -X POST http://localhost:3000/api/v1/ingest \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: troque-esta-chave" \
  -d '{ "source": "FortiSIEM", "rule": "DNS tunneling detectado",
        "severity": "critical", "srcIp": "10.2.1.40",
        "dstIp": "91.240.118.172", "user": "svc.pix",
        "host": "SRV-PIX-01", "tenant": "atlantico" }'
```

Na FortiSIEM, aponte uma **regra de notificação** (HTTP POST) para este
endpoint. Aceita o modelo SOPIR ou campos nativos (`srcIpAddr`,
`destIpAddr`, `eventType`, `eventSeverity`…).

## API (resumo)

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/v1/health` | health check |
| GET | `/api/v1/bootstrap?tenant=` | snapshot completo (hidratação do frontend) |
| GET | `/api/v1/events?q=&severity=&source=&from=&to=` | busca de eventos |
| GET | `/api/v1/events/:id/related` | eventos correlacionados |
| POST | `/api/v1/ingest` | ingestão push (X-Api-Key) |
| GET/POST/PATCH | `/api/v1/alerts` | alertas + `POST /alerts/:id/escalate` |
| GET/POST/PATCH | `/api/v1/incidents` | incidentes + tarefas + abrir case |
| GET/POST/PATCH | `/api/v1/cases` | cases + comentários |
| GET/PATCH | `/api/v1/vulnerabilities` | findings |
| GET/PATCH | `/api/v1/assets` | inventário + isolamento |
| GET | `/api/v1/playbooks` · `/api/v1/runs` | SOAR |
| POST | `/api/v1/playbooks/:id/run` · `/runs/:id/approve` · `/reject` | Response Engine |
| GET | `/api/v1/correlations` · PATCH `/correlations/:id` | motor de correlação |
| GET/POST/PATCH/DELETE | `/api/v1/admin/connectors` (+ `/types`, `/test`) | **connectors por cliente** |
| GET | `/api/v1/graph/expand?type=&value=&tenant=` | expansão do Investigation Graph |
| GET/POST/PATCH | `/api/v1/investigations` | investigações salvas (grafo persistido) |
| GET | `/api/v1/audit` · `/api/v1/connectors` | trilha + saúde dos collectors |

Todas as respostas usam o **modelo normalizado do SOPIR** (camelCase), o
mesmo consumido pelo frontend.

## Autenticação JWT + RBAC

Login com bcrypt → JWT (12h) carregando `{ sub, name, role, tenant }`.
Todas as rotas (exceto `/health` e `/ingest`, que usa API-key) exigem
`Authorization: Bearer <token>`. Mutações são protegidas por permissão
granular (`alerts.update`, `response.approve`, `correlations.update`…).
O papel **Customer** fica preso ao próprio tenant — jamais enxerga outro
cliente (escopo vem da claim do token, não da query).

Usuários de demonstração (senha única `sopir`):

| usuário | papel |
|---|---|
| `luiz.almeida` | Admin |
| `ana.ribeiro` | SOC Manager |
| `carlos.mendes` | SOC Analyst |
| `marina.sousa` | Security Engineer |
| `cliente.vetra` | Customer (só vê o tenant Vetra) |

```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{ "username": "luiz.almeida", "password": "sopir" }'
```

## Motor de correlação por política

Alertas nascem de **padrões**, não de severidade isolada. Cada política
define janela deslizante + `groupBy` + threshold; quando o grupo acumula
eventos suficientes, o motor dispara um alerta (com cooldown para não
repetir) e audita. Políticas podem ser ativadas/desativadas via
`GET/PATCH /api/v1/correlations` (requer `correlations.update`).

```bash
# com token de Admin/Manager
curl http://localhost:3000/api/v1/correlations -H "Authorization: Bearer $TOKEN"
```

## Investigation Graph

O diferencial do SOPIR: a partir de uma semente (IP, usuário, host, regra,
IOC ou incidente), o motor de grafo (`src/graph.js`) expande as entidades
relacionadas navegando pelas tabelas de eventos, alertas, incidentes e IOCs.
Processos são **derivados da regra** (enriquecimento), revelando a cadeia
`IP → usuário → endpoint → processo → evento → IOC → incidente`.

- `GET /api/v1/graph/expand?type=host&value=WS-FIN-014&tenant=vetra` → nós + arestas
- O grafo construído no frontend pode ser **salvo** (`POST /investigations`,
  snapshot JSON) e recarregado; requer `investigations.read/update`.

No frontend, o canvas é force-directed (SVG puro, sem libs): arraste nós,
duplo clique expande, roda do mouse dá zoom, fundo arrasta a visão.

## Connectors por cliente (Integrações)

Cada cliente pode ter suas próprias fontes, configuradas pela tela
**Connectors** (ou via `/api/v1/admin/connectors`):

| Tipo | Coleta | Campos |
|---|---|---|
| `wazuh_indexer` | poll `_search` no Indexer/OpenSearch | url, user, pass, indexPattern |
| `wazuh_manager` | Manager API 4.8+ (JWT + `GET /events`) | url, user, pass |
| `fortisiem` | Phoenix REST (login + eventos) | url, user, pass, org |
| `webhook` | **push** — a fonte POSTa em `/api/v1/ingest` | — |

- Cada instância alimenta **um tenant específico** (ex.: "Wazuh — Vetra").
- Configurações ficam na tabela `connector_configs`; **senhas nunca retornam**
  na API (mascaradas) e um valor mascarado no update preserva a senha atual.
- O scheduler recarrega as configurações a cada 30s — um connector criado na
  UI entra em coleta sem reiniciar a API.
- `POST /admin/connectors/test` valida a conexão **antes** de salvar.
- Permissões: `connectors.read` (ver) / `connectors.update` (gerir).

Exemplo — cliente C com FortiSIEM:

```bash
curl -X POST http://localhost:3000/api/v1/admin/connectors \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{ "name": "FortiSIEM — Medcore", "type": "fortisiem", "tenant": "medcore",
        "settings": { "url": "https://fortisiem:443", "user": "admin", "pass": "***" },
        "pollSeconds": 30 }'
```

## Audit & Compliance

A trilha de auditoria é **à prova de adulteração** (tamper-evident):

- **Cadeia de hashes**: cada registro carrega um SHA-256 sobre
  `(hash anterior + ts + ator + ação + alvo + tipo)`. Qualquer alteração de um
  registro quebra a verificação dali em diante — o endpoint
  `GET /audit/verify` recomputa a cadeia e aponta o primeiro registro violado.
  Registros antigos são **selados** automaticamente no boot (idempotente).
- **Enriquecimento automático**: cada ação grava IP, user-agent e sessão
  (via `AsyncLocalStorage`), resultado (`ok`/`denied`) e **diff antes/depois**
  nas mutações (alertas, incidentes, vulnerabilidades, ativos).
- **Controles de compliance**: cada ação é tagueada com um controle de
  referência (base SOC 2 / ISO 27001: CC6.1, CC6.6, CC7.2-7.4, CC8.1).
- **Painel de conformidade** (`GET /audit/compliance`): cobertura por controle,
  volume diário (14 dias) e sinais de risco (logins negados, acessos
  cross-tenant bloqueados, ações fora de horário, respostas rejeitadas).
- **Filtros** (`GET /audit`): texto, tipo, ator, resultado, controle, período.

Permissão: `audit.read` (exportação CSV/JSON incluída).

## Detection & Correlation

O motor de correlação foi expandido para suportar **regras customizáveis**,
**risk scoring** e **agrupamento**:

- **Regras customizáveis** (`correlation_policies`): CRUD completo via
  `POST/PUT/DELETE /api/v1/correlations`. Cada regra é declarativa
  (janela, threshold, groupBy, condições de match, modo `count`/`distinct`,
  tag MITRE) e convertida em avaliador em runtime. Regras embutidas seguem
  ativas e não são editáveis/removíveis.
- **Backtest**: `POST /api/v1/correlations/backtest` executa uma definição
  contra os eventos recentes do buffer (sem criar alertas) e retorna os
  grupos que teriam disparado.
- **Risk scoring**: `GET /api/v1/risk/scores?type=host|srcIp|user` combina
  eventos 24h (peso por severidade), alertas abertos, incidentes ativos e
  vulnerabilidades críticas em um score 0–100 por entidade.
- **Agrupamento**: `GET /api/v1/events/aggregate?by=host|srcIp|user|rule&hours=N`
  agrega eventos com distribuição de severidade e janela de ocorrência.

No frontend, a página **Correlação** tem 4 abas: Regras (CRUD + backtest),
Agrupamento, Risco e Disparos — com fallback client-side em modo demonstração.

## Próximas fases

- Collectors adicionais: FortiGate, Microsoft Defender, CrowdStrike, scanners (DefectDojo-like)
- Relatórios agendados + exportação server-side (PDF real)
- Sequências ordenadas no motor de correlação (A depois B depois C)
