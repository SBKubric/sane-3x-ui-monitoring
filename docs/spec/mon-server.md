# mon-server

Спека и план реализации. Итог карты [Healthcheck-мониторинг inbound'ов: mon-server, mon-clients и контракт с панелью](https://github.com/SBKubric/3ax-ui-proxy/issues/20); решения приняты в её тикетах, здесь они только собраны. Термины по [CONTEXT.md](../../CONTEXT.md). Wire-формы: к панели — [Контракт API панели для mon-server](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/spec/monitoring-contract.md) (далее «контракт»), к mon-clients — [mon-protocol.md](mon-protocol.md) (далее «протокол»). Принцип: mon-server — реестр и единственный источник истины мониторинга, панель — пассивный приёмник ([ADR 0003](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/adr/0003-mon-server-single-source-panel-passive.md)).

## 1. Назначение и границы

mon-server — один Go-процесс на отдельном сервере с публичным IP. Он:

- раз в минуту poll'ит панель (`GET /state`, `POST /probe/ensure`), при смене ревизии панели забирает конфиги probe-набора (`GET /probe/configs` по каждому path: `direct` и каждое пробируемое звено цепочки, на панели без цепочки — `proxy`, §5.1) и пересобирает конфиг каждого mon-client;
- ведёт реестр mon-clients: registration requests с pairing code, одобрение и замена в admin UI, client tokens, paths и enable per-client;
- принимает heartbeat и tunnel probes, считает state machine targets и mon-clients, шлёт панели события и 5-минутные агрегаты;
- при недоступности панели (`PANEL_DOWN`) сам шлёт Telegram и копит события для досылки;
- отдаёт admin UI за логином.

Вне scope v1: несколько mon-server на панель и один mon-server на несколько панелей; пробы WireGuard и MTProto; мониторинг sub-сервера proxy front; показ состояния targets в admin UI (картина только в панели).

## 2. Процесс, bootstrap и CLI

- Один бинарник `mon-server`, Go, без внешних сервисов. Команды: `mon-server run` (сервис), `mon-server admin set <user>` (запрашивает пароль, пишет bcrypt-хэш в БД; повторный вызов меняет логин и пароль), `mon-server version`.
- **Bootstrap-конфиг** (файл `/etc/mon-server/config.json` или ENV `MON_*`) минимален: `listen` (`:443`), `publicIp` (обязателен в обоих режимах TLS, IP-литерал: из него строится `probeUrl` = `https://<publicIp>:<port>/v1/probe`, параметра `publicHost` нет — AWG-проба в netstack не резолвит имена), `dataDir` (`/var/lib/mon-server`), `tls.mode` (`acme-ip` | `files`, для `files` — `tls.cert`, `tls.key`), `tls.acmeCa` / `MON_TLS_ACME_CA` (`production` по умолчанию | `staging` | URL ACME directory, §2.1). Всё остальное — в настройках БД через admin UI (§9.4).
- **Права на `dataDir`.** В БД лежат `monToken` и `tgToken`, поэтому на каждом старте (и в `admin set`) mon-server создаёт `dataDir` с `0700` и выставляет `chmod` `dataDir` → `0700`, `mon-server.db` → `0600` — идемпотентно, чинит и существующую установку с более широкими правами. `dataDir/certs` certmagic сам держит в `0700`/`0600`. В systemd-юните дополнительно `StateDirectoryMode=0700` и `UMask=0077` (README).
- **Один листенер** HTTPS на `listen`: `/v1/*` для mon-clients (протокол), `/admin/*` для admin UI, `/healthz` без auth (только `200`). Heartbeat, регистрация и конфиг идут мимо туннелей, tunnel probe — через туннель target'а; различаются путями, не портами.
- Graceful shutdown: дождаться текущих обработчиков, буферы в SQLite (§3) уже durable.

### 2.1 TLS

`tls.mode = acme-ip` (default): встроенный certmagic — сертификат Let's Encrypt для IP-адреса, профиль `shortlived` (160 ч), challenge `tls-alpn-01` на том же `:443`, `DisableHTTPChallenge: true` (`:80` не нужен), `RenewalWindowRatio ≈ 0.5` (продление каждые ~3 дня), `FileStorage` в `dataDir/certs`. Требования к коробке: `:443` открыт всему интернету (валидаторы LE), NTP.

CA задаёт `tls.acmeCa` / `MON_TLS_ACME_CA`: `production` (default) — боевой Let's Encrypt; `staging` — staging Let's Encrypt (стенды, которые пересобираются чаще, чем позволяют лимиты боевого LE на один IP: 5 сертификатов на набор идентификаторов за 7 дней); любое другое значение — URL ACME directory (Pebble в e2e/CI). Профиль `shortlived`, IP-SAN и `tls-alpn-01` со staging совместимы. Storage certmagic разделён по host CA, staging и production не пересекаются. С `production` certmagic повторные попытки сначала валидирует на staging (неявный `TestCA`) — в логах ретраев виден staging-host. Admin UI показывает CA на табе «TLS & admin» (§9.4).

`tls.mode = files` — свой cert/key (домен или тесты), без ACME. Лист сертификата обязан содержать IP-SAN, равный `publicIp` (mon-clients ходят на `probeUrl` по IP); иначе старт падает с ошибкой `cert has no IP SAN for publicIp`.

mon-client проверяет сертификат системными CA, пиннинга нет и CA-флага нет. Сертификат от staging-CA mon-client доверяет только через окружение: `SSL_CERT_FILE` с корнями staging LE (Go при этом продолжает читать `/etc/ssl/certs`) — см. README.

## 3. Хранилище

SQLite одним файлом `dataDir/mon-server.db` (GORM, как у панели; `foreign_keys=ON`, busy timeout 5 с, одно соединение на запись). Времена — ms UTC. Индексы с префиксом `idx_ms_`.

| таблица | ключ | поля | назначение |
|---|---|---|---|
| `settings` | `key` PK | `value` | настройки §9.4 (kv, как у панели) |
| `admin` | одна строка | `username`, `password_hash` (bcrypt), `updated_at` | администратор |
| `admin_sessions` | `id` (случайные 32 байта, cookie) | `created_at`, `expires_at` (24 ч), `ip` | cookie-сессии |
| `login_attempts` | `ip` PK | `failures`, `locked_until` | 5 неудач → 15 мин |
| `registration_requests` | `request_id` PK (128 бит base64url) | `pairing_code`, `hostname`, `version`, `public_ip`, `remote_ip`, `status` (`pending`/`approved`/`rejected`/`expired`), `created_at`, `expires_at` (+5 мин), `approved_token` (одноразовая выдача), `mon_client_id` | заявки §6 |
| `mon_clients` | `id` (slug ≤ 32 `[A-Za-z0-9_-]`) PK | `name`, `region`, `paths` (JSON словаря §5.1, default `["edges"]`), `token_hash` (SHA-256), `enabled`, `state` (`ONLINE`/`OFFLINE`/`NEVER`), `last_heartbeat`, `version`, `xray_version`, `applied_revision`, `config_error`, `config_error_at`, `rejected_targets` (JSON `[{target, error}]` из последнего heartbeat), `unallocated` (JSON `[{path, reason}]` из последнего ответа ensure, §4 шаг 2), `remote_ip`, `approved_at`, `missed_heartbeats` | реестр |
| `targets` | unique `(mon_client_id, inbound_kind, inbound_id, path)` | `state` (`UP`/`DOWN`/`FLAPPING`/`UNKNOWN`/`PAUSED`), `since`, `reason`, `consecutive_fail`, `consecutive_ok`, `transitions` (JSON последних времён переходов для FLAPPING), `flapping_until`, `last_result_at` | state machine §7 |
| `panel_inbounds` | `(inbound_kind, inbound_id)` | `protocol`, `port`, `remark`, `enable`, `seen_revision` | последний `GET /state` |
| `client_configs` | `mon_client_id` PK | `revision`, `document` (JSON §5), `built_at` | собранный конфиг per-client |
| `events_outbox` | `id` UUID v7 PK | `ts`, `payload` (JSON события контракта §4.6), `notified`, `sent_at` (NULL пока не подтверждено панелью), `dropped` (панель отвергла, см. §4 шаг 4) | очередь событий, в `PANEL_DOWN` — буфер до 24 ч |
| `stats_buckets` | unique `(mon_client_id, inbound_kind, inbound_id, path, bucket_start)` | `n_ok`, `n_fail`, `lat_min`, `lat_avg`, `lat_max`, `handshake_ms`, `sent_at`, `dropped` | 5-мин агрегаты до отправки и на случай повтора |
| `probe_seen` | `id` autoinc | `mon_client_id`, `inbound_kind`, `inbound_id`, `path`, `egress_ip`, `seen_at` | лог приходов tunnel probe (диагностика), ретеншн 24 ч |

`path` в `targets`, `stats_buckets` и `probe_seen` — строка по грамматике §5.1 (`inner:` + имя звена до 32 символов), колонки по длине не урезаются. Миграция словаря paths ([#61](https://github.com/SBKubric/3ax-ui-monitoring/issues/61) п. 3): сохранённый `proxy` в `mon_clients.paths` один раз переписывается в `hops`.

Ретеншн (job раз в час): `events_outbox` с `sent_at` старше 7 дней, `stats_buckets` с `sent_at` старше 7 дней, `probe_seen` старше 24 ч, `registration_requests` не-pending старше 7 дней, `admin_sessions` истёкшие.

## 4. Цикл с панелью

Клиент панели: base URL из настроек (§9.4), `Authorization: Bearer <monToken>`, таймаут 10 с, ретраи только на сеть/5xx/таймаут с экспоненциальной задержкой (1 → 2 → 4 с, не дольше минуты цикла); `4xx` на батч целиком — лог и дроп батча (`dropped`). Голый `404` на `GET /state` = «неверный токен, путь или мониторинг выключен» → Telegram от mon-server (§10), состояние `PANEL_DOWN` не объявляется (панель отвечает).

Раз в минуту (`panel poll`):

1. `GET /state` → сохранить `panel_inbounds`, override, `chain`, `probe.subId`, `revision`. Ревизия отличается от последней виденной → шаг 3. **Версия контракта** — строгое совпадение (решения [#80](https://github.com/SBKubric/3ax-ui-monitoring/issues/80) п. 9, [#61](https://github.com/SBKubric/3ax-ui-monitoring/issues/61) п. 5): принимается только `contract == 3`; `contract` ≠ 3 (и меньше, и больше) или поля нет (= контракт 1) → шаги 2–3 не выполняются (ни ensure, ни `panel_inbounds`, ни probe-материала — targets не строятся), в лог и в статус Settings (§9.4) идёт `panel speaks monitoring contract N, mon-server needs 3 — update the panel` (для `contract` > 3 — `… — update mon-server`); очередь шага 4 отправляется как обычно, `PANEL_DOWN` не объявляется (панель отвечает). Панель и mon-server обновляются вместе (версии пинятся в ansible); окно между обновлениями видно как эта ошибка в Settings → Check. Контракт 3 добавляет `chain {revision, activeEdge, hops[{name, role, host, state}]}` в `/state` и в ревизию, `?hop=` у `/probe/configs` и лимит AWG probe-пиров — без них per-hop targets не построить (§5.1).
2. `POST /probe/ensure` с полным снимком реестра: `{id, name, region, state, lastHeartbeat, paths}` по всем mon-clients с `enabled=true` (выключенные и `NEVER` тоже входят: панель показывает их как есть). Ответ несёт `subId` и `revision`; `503 xray_unavailable` — повторить в следующем цикле. `paths` — все path'ы, на которых mon-client держит targets (§5.1), словами, которые панель раскрывает сама (`direct`, `hops`, явные звенья): словарь mon-client как есть, а `edges` в нём уходит как `direct` + `hops` — probe accounts и AWG-пиры по всем path цепочки держатся всегда, чтобы diagnostic sweep было чем проверять (решение [#100](https://github.com/SBKubric/3ax-ui-monitoring/issues/100)). Панель заводит AWG probe-пир только на эти пары mon-client × path, в том числе на звенья цепочки (решения [#80](https://github.com/SBKubric/3ax-ui-monitoring/issues/80), [#61](https://github.com/SBKubric/3ax-ui-monitoring/issues/61)), в пределах своей настройки `monProbePeerLimit` ([#61](https://github.com/SBKubric/3ax-ui-monitoring/issues/61) п. 4; кому пир достаётся первым — контракт §4.3, выдачу решает панель). Смена `paths` у mon-client уходит в следующий ensure; панель сверяет пиры, ревизия сдвигается, и материал перечитывается по шагу 3. При исчерпанном пуле адресов или лимите ensure всё равно `200`, а `unallocated` называет пары без пира, у каждой — `reason`: `pool_exhausted` (кончились адреса пула AWG-сервера) или `limit` (превышен `monProbePeerLimit`); форма — контракт §4.3. mon-server пишет лог `WARN`, сохраняет список в `mon_clients.unallocated` (для admin UI, §9.3), а AWG-targets этих пар уходят в `PAUSED no_probe_link` (§5, §7).
3. При смене ревизии, при смене `realHost` (он не входит в ревизию панели, но в direct-ссылки входит) и после Save `realHost`/`panelUrl` в Settings (§9.4; решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 4): `GET /probe/configs?host=<realHost>` (path `direct`) и материал остальных path'ов (§5.1): с цепочкой — `GET /probe/configs?hop=<name>` на каждое пробируемое звено (path `edge:<name>` / `inner:<name>` по `role`), без цепочки — `GET /probe/configs` (path `proxy`), если `override.enabled`. Ответ с `revision` ≠ текущей, как и `409 unknown_hop` / `409 hop_not_joined` (реестр цепочки сменился между `/state` и запросом), отбросить и повторить в следующем цикле. С контракта 2 ревизия панели покрывает весь probe-материал, включая набор AWG probe-пиров, а с контракта 3 — и `chain` (звенья, их состояния, active edge), поэтому новый mon-client, выданный пир или изменение цепочки тоже двигают ревизию, и перечитывание только по её смене остаётся достаточным; `chain.revision` отдельно не отслеживается. Пересобрать `client_configs` всех mon-clients (§5). Inbound'ы, исчезнувшие из `/state`, — снять их targets (`PAUSED` → удалить строки после подтверждения следующим heartbeat без этих targets); inbound'ы с `enable=false` есть в `/state`, но не в `items` → их targets `PAUSED` с событием `config_disabled`.
4. Отправка очереди: `POST /events` батчами ≤ 1000 из `events_outbox` с `sent_at IS NULL` (по `ts`), `POST /stats` для закрытых бакетов с `sent_at IS NULL` (≤ 2000). Панель отвечает поэлементно: `200 {accepted, rejected: [{index, id?, error}]}` (`id` — только у событий; решение [#50](https://github.com/SBKubric/3ax-ui-monitoring/issues/50)). Принятые → `sent_at = now`; отвергнутые → лог `WARN` с `error` панели, `sent_at = now` и `dropped = true`, без повторов (повтор был бы отвергнут так же). Пустое тело `200` (панель до поэлементной валидации) = «все приняты». Дубликаты и `ignored` панели — лог, не ошибка. `400 invalid_body` на батч целиком остаётся для нечитаемого тела — дроп батча, как любой `4xx`. В ответе `POST /stats` панель может назвать target'ы, по которым у неё нет состояния (необязательное поле `resync`) — на них mon-server шлёт сверку состояния (§7.2).

### 4.1 `PANEL_DOWN`

3 неудачных подряд запроса к панели (любых) → режим `PANEL_DOWN`: событие `{kind: panel, from: PANEL_UP, to: PANEL_DOWN, reason: http_timeout|http_5xx|conn_refused, notified: true}` в outbox, одно сообщение «panel unreachable» в Telegram от mon-server. В режиме: переходы targets и mon-clients mon-server **сам** шлёт в Telegram с пометкой «via mon-server» и помечает `notified=true`; события копятся в outbox (ограничение 24 ч — старше отбрасываются с логом), бакеты копятся без ограничения ретеншном 7 дней. Poll `GET /state` продолжается раз в минуту — он и есть детектор возврата. Первый успешный запрос → `PANEL_UP` (событие с `notified: true`), досылка outbox батчами с исходными `ts`, сообщение «panel back, N событий дослано».

## 5. Конфиг mon-client и config revision

Для каждого mon-client документ протокола §4.2:

- `targets` = `items` из `/probe/configs` для каждого path, в который раскрываются `paths` этого mon-client (§5.1; path'ы, которые держатся без проб, — `direct` и `inner:*` у mon-client на `edges` — в `targets` не входят); `link`/`conf` отдаются **как есть** (панель уже подставила адрес по path). Все inbound'ы — всем mon-clients; фильтра по inbound'ам в v1 нет. **AWG — per mon-client** (решение [#80](https://github.com/SBKubric/3ax-ui-monitoring/issues/80) п. 1, 7): xray-items общие для всех (у них нет `monClientId`), а из AWG-items path'а mon-client получает только item со своим `monClientId` — AWG probe-пир у каждого mon-client × path свой. Нет своего AWG-item на path (пул исчерпан или превышен `monProbePeerLimit` панели — `unallocated` с `reason`, §4 шаг 2; ensure ещё не дошёл) → AWG-target'а в конфиге нет, он `PAUSED no_probe_link` (§7); AWG-item без `monClientId` не достаётся никому.
- `probe` — глобальные параметры из настроек (§9.4): `intervalMs 60000`, `budgetMs 20000`, `connectMs 5000`, `tlsMs 10000`, `headersMs 10000`, `startJitterMs 5000`, `heartbeatTimeoutMs 10000`.
- `probeUrl` = `https://<publicIp>:<port>/v1/probe`.
- **`configRevision`** = первые 16 hex SHA-256 канонического JSON документа без поля `configRevision`. Меняется при смене материала панели для этого mon-client (ревизия панели, которая его не меняет, — например, переключение active edge, §5.1 — config revision не двигает), `paths` mon-client, `probe`-параметров или `probeUrl`. Пороги state machine в конфиг не входят.

Документ хранится в `client_configs`; `GET /v1/config` отдаёт его, ответ heartbeat несёт только `configRevision`.

### 5.1 Paths по цепочке

Решение [#61](https://github.com/SBKubric/3ax-ui-monitoring/issues/61); панельная сторона — [proxy-chain.md](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/spec/proxy-chain.md) §6 и контракт 3. Термины цепочки (chain, hop, edge front, inner front, active edge) — по [CONTEXT.md](../../CONTEXT.md).

**Грамматика path**: `direct` | `proxy` | `edge:<name>` | `inner:<name>`, где `<name>` — имя звена в реестре цепочки (`[a-z0-9-]{1,32}`). На проводе к mon-client — как есть (протокол §4.2).

**Пробируемые path'ы** — по последнему `GET /state`:

| панель | path'ы | `GET /probe/configs` |
|---|---|---|
| с цепочкой (`chain.hops` не пуст) | `direct`; `edge:<name>` / `inner:<name>` на каждое звено в состоянии `joined` или `legacy` (префикс — по `role`) | `?host=<realHost>`; `?hop=<name>` на звено |
| без цепочки (`chain` нет или `hops` пуст: звеньев в реестре нет, адрес proxy — только из host override) | `direct`; `proxy` при `override.enabled` | `?host=<realHost>`; без параметров |

- Звенья в `pending` (в том числе перевход) и `draining` не пробируются: снятие звена — действие оператора, алерты в процессе — шум.
- С цепочкой `proxy` отдельным target'ом не держится — его заменяет `edge:<active>`. Пробируются все edge, и active, и standby, поэтому переключение active edge переходов не даёт: набор targets и их ссылки прежние, config revision mon-clients не меняется. Строки панели под старым `proxy` уходят её ретеншном.

**`paths` mon-client** — словарь, который раскрывается в пробируемые path'ы при каждой сборке конфига:

| значение | раскрывается в |
|---|---|
| `direct` | `direct` |
| `edges` | все пробируемые edge, active и standby, включая появившиеся позже; на панели без цепочки — `proxy`. Остальные path'ы цепочки (`direct`, все `inner:*`) mon-client держит без проб (см. ниже) |
| `hops` | все пробируемые звенья, включая появившиеся позже; на панели без цепочки — `proxy` |
| `edge:<name>`, `inner:<name>` | это звено, пока оно пробируется; иначе ничего |

- Default при одобрении (admin UI §9.2 и авто-одобрение из ansible) — `["edges"]` (решение [#100](https://github.com/SBKubric/3ax-ui-monitoring/issues/100)); mon-clients, сохранённые с явным `paths` (в том числе прежним default `["direct","hops"]`), его сохраняют. Явные имена ограничивают коробку частью звеньев (inner доступен не из каждого региона); `direct` на коробках во враждебных регионах владелец снимает, чтобы не светить настоящий адрес real server как Reality-endpoint.
- **Path'ы без проб** (решение [#100](https://github.com/SBKubric/3ax-ui-monitoring/issues/100)): у mon-client, в `paths` которого есть `edges`, targets держатся на всех path'ах цепочки (`direct` и каждое звено), а каждый цикл пробируются только раскрытые из словаря. Остальные — `direct` и `inner:*` — не `PAUSED` и не удаляются: их строки `targets` создаются `UNKNOWN`, в конфиг mon-client не входят (AWG — только при своём item'е, как в §5; без него — `PAUSED no_probe_link`). `inner:*` показывает **derived state** (§7.2), `direct` — результат последнего diagnostic sweep (до первого — `UNKNOWN`). В снимок ensure такой mon-client уходит со словарём `direct` + `hops` (§4 шаг 2).
- `proxy` в словарь не входит: сохранённый `proxy` мигрирует в `hops` (§3), и на панели без цепочки поведение прежнее.
- Совпавшие после раскрытия path'ы (`hops` и явное имя) дают один target.

**Targets** = inbound'ы × раскрытые path'ы (AWG — только со своим item'ом, §5).

**Звено ушло из пробируемых** — удалено, переименовано (переименование = удаление + добавление) или, оставаясь в реестре, перешло в `pending` (перевыпуск токена, перевход) или `draining` — либо ушёл `proxy`, когда у цепочки появилось пробируемое звено: строки `targets` этих path'ов mon-server удаляет молча, без событий панели и без Telegram. Звено, снова вошедшее в пробируемые (после перевхода), начинает с новых targets в `UNKNOWN`. Свои строки `mon_targets` для path'ов, которые больше не пробируются, панель удаляет сама в той же транзакции, что и изменение реестра ([proxy-chain.md](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/spec/proxy-chain.md) §6.1). Это не `path_removed`: та пауза — для path'а, который панель по-прежнему пробирует, но который убран из `paths` mon-client (§7.2).

**Известный пробел**: active edge, переведённое в `pending` перевыпуском токена, продолжает держать host override (клиенты ходят через него), но не мониторится, пока не войдёт заново.

**AWG probe-пиры** — на mon-client × path, в том числе на каждое звено (правило [#80](https://github.com/SBKubric/3ax-ui-monitoring/issues/80)), и только на пары, которые этот mon-client действительно пробирует: `paths` едут панели в снимке ensure (§4 шаг 2). Сколько пиров выдать и кому, решает панель: сверх её настройки `monProbePeerLimit` пиры не выдаются (порядок выдачи — контракт §4.3), и mon-client × path без пира получает `PAUSED no_probe_link` (§7.2) с причиной `pool_exhausted` или `limit` из `unallocated`, видной в admin UI (§9.3).

**Агрегаты по звену** — худшее состояние звена, «большинство UP», бейджи, Telegram-подсказки о запасном edge — считает только панель ([proxy-chain.md](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/spec/proxy-chain.md) §6.4–6.5). mon-server шлёт события и статистику по path и агрегатов не считает; admin UI — колонка path и фильтр по ней (§9.3).

## 6. Регистрация, токены, реестр

Протокол §2–3, admin UI §9.

- `POST /v1/register`: rate limit **1 заявка/мин на IP**, ≤ **3 pending с IP**, ≤ **20 pending глобально** (`429` + `Retry-After`); pairing code `[A-Z2-9]{6}` от mon-client; ответ `202 {requestId, pollAfter: 10000, expiresAt}`; заявка живёт 5 мин, потом `status=expired` и `410` на опрос. Неверный `requestId` — `404` без деталей.
- Одобрение (admin UI): администратор сверяет код с логом коробки, вводит `name`, `region`, выбирает paths (словарь §5.1, default `["direct","hops"]`) → `monClientId` = slug имени (уникальный, ≤ 32 `[A-Za-z0-9_-]` — из него панель называет AWG probe-пиры, решение [#80](https://github.com/SBKubric/3ax-ui-monitoring/issues/80)), client token = 32 случайных байта (base64url), в БД только SHA-256; `approved_token` хранится в заявке до первого `GET /v1/register/<id>` со статусом `approved`, затем стирается. **Approve as replacement**: выбранный существующий mon-client сохраняет id, историю, paths, name и region; его `token_hash` заменяется (старый токен отозван), `state=NEVER` до первого heartbeat. **Seq привязан к поколению токена** (решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 1): при каждой выдаче токена — Approve и Approve as replacement (в том числе после Revoke) — `last_ack_seq = 0`; новая регистрация mon-client начинает с `seq=1`, и её циклы не отбрасываются как дубликаты циклов прежнего токена. Подсказка: при совпадении `hostname` или `public_ip` заявки с существующим mon-client admin UI предлагает замену, режим выбирает администратор явно. Reject → `status=rejected`, mon-client ждёт 1 ч.
- Аутентификация `/v1/config`, `/v1/heartbeat`, `/v1/probe`: `Bearer <token>` → SHA-256 → поиск по `token_hash` (constant-time сравнение). Неизвестен/отозван → `401 token_revoked`; известен, но `enabled=false` → `403 disabled`.
- **Revoke** (admin UI): `token_hash` очищается, mon-client остаётся в реестре со `state=OFFLINE` до новой заявки (одобрить её как replacement, чтобы вернуть id). Revoke идёт через state machine (§7.3, решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 2): в той же транзакции — событие `mon_client` `→ OFFLINE` с `reason: token_revoked` (если клиент ещё не `OFFLINE`; из `NEVER` — с пустым `from`), targets → `UNKNOWN` с `reason: mon_client_revoked`, Telegram — как у `OFFLINE` по таймауту. **Delete** mon-client: строка и его targets удаляются, панель чистит по следующему снимку. **Disable**: `enabled=false`, targets → `UNKNOWN` (событие `reason: mon_client_disabled`), из снимка реестра не исключается.

## 7. Heartbeat, state machine, статистика

Протокол §5; пороги из [State machine target'а](https://github.com/SBKubric/3ax-ui-proxy/issues/22).

### 7.1 Приём heartbeat

1. `received_at = now` (время mon-server — авторитет для состояния); `ts` циклов клампится к `received_at` при расхождении > 5 мин и используется только для раскладки по бакетам.
2. mon-client: `last_heartbeat = now`, `state=ONLINE` (из `OFFLINE`/`NEVER` — событие `mon_client ONLINE`; первый переход, из `NEVER`, уходит панели с пустым `from` — `NEVER` внутреннее состояние реестра и наружу не отдаётся, словарь панели для `mon_client` — `ONLINE`/`OFFLINE`), `version`, `xrayVersion`, `configError` (появился → событие в лог реестра + Telegram от mon-server §10; исчез → очистить), `rejectedTargets` (сохраняется как прислан, для admin UI; targets текущего конфига из него → `PAUSED config_error`, §7.2; Telegram нет). `configRevision` в heartbeat ≠ актуальной → `applied_revision` в реестре помечается как отстающая (видно в admin UI).
3. Циклы с `seq ≤ ackSeq` предыдущего ответа (`last_ack_seq`, сбрасывается при выдаче токена, §6) игнорируются. Из новых: **живой цикл** (последний, пришедший своим heartbeat, `unverified=false`) применяется к state machine; **досланные** (`seq` ниже последнего) и **unverified** идут только в статистику; из unverified берутся только успехи, провалы — пропуск. Результаты по targets, которых нет в текущем конфиге mon-client, отбрасываются.
4. Ответ `{configRevision, serverTs, ackSeq: max seq}`.

### 7.2 State machine target (считает mon-server)

| состояние | вход | выход | событие панели / Telegram |
|---|---|---|---|
| `UNKNOWN` | новый target; mon-client `OFFLINE`/disabled | в `UP` — с первого успеха живого цикла; в `DOWN` — только после `downAfter` провалов подряд (провалы до порога оставляют `UNKNOWN`) | событие; Telegram нет |
| `UP` | `upAfter` (2) успехов подряд из `DOWN`; из `UNKNOWN` — первый успех | — | «UP» с длительностью простоя (только из `DOWN`) |
| `DOWN` | `downAfter` (3) провала подряд при живом heartbeat — из `UP` и из `UNKNOWN` одинаково | — | «DOWN» с `reason` из результата |
| `FLAPPING` | ≥ `flapN` (4) переходов UP↔DOWN за `flapMin` (30 мин) | `flapHoldMin` (15) без переходов → фактическое состояние; выход проверяется только при приходе результата живого цикла (таймера нет: без результатов target остаётся `FLAPPING`, первый результат после истечения выводит его и применяется уже к фактическому состоянию) | одно сообщение при входе и выходе; переходы внутри — только события |
| `PAUSED` | inbound `enable=false` или пропал из `/probe/configs` (`config_disabled`); target выпал из собранного конфига mon-client по не-inbound причине (решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 3): `override_disabled` (выключен host override, path `proxy` — только на панели без цепочки), `path_removed` (у mon-client убран path, который панель по-прежнему пробирует; path ушедшего звена — не пауза, а молчаливое удаление, §5.1), `no_probe_link` (inbound включён, но панель не выдала на этот path probe-ссылку; для AWG — нет item'а со своим `monClientId`, например пара в `unallocated` ensure с `reason` `pool_exhausted` или `limit` (сверх `monProbePeerLimit` панели) — в панель уходит только `no_probe_link`, причину показывает admin UI §9.3; решение [#80](https://github.com/SBKubric/3ax-ui-monitoring/issues/80) п. 10: у AWG-target'а без строки она создаётся `UNKNOWN`, событие `UNKNOWN → PAUSED`, с первого heartbeat); target текущего конфига mon-client есть в `client.rejectedTargets` heartbeat'а (`config_error`, решение [#53](https://github.com/SBKubric/3ax-ui-monitoring/issues/53) п. 3; у target'а без строки она создаётся `UNKNOWN`, событие `UNKNOWN → PAUSED`); строка не удаляется | inbound снова активен → `UNKNOWN` (`config_enabled`, только для `config_disabled`); target снова в конфиге mon-client → `UNKNOWN` (`config_enabled`, для не-inbound причин; проверяется при каждом heartbeat); target пропал из `rejectedTargets` при той же или новой ревизии → `UNKNOWN` (`config_enabled`); затем первый результат | событие с `reason` причины / `config_enabled`; Telegram нет |

Пороги глобальные в настройках (§9.4). Каждый переход → событие контракта §4.6 в outbox: `{id: UUID v7, ts: received_at, kind: target, monClientId, inboundKind, inboundId, path, from, to, reason, notified}`; `reason` из словаря (`tcp_refused` `tcp_timeout` `tls_timeout` `reality_real_cert` `awg_no_handshake` `http_error` `recovered` `flapping` `config_disabled` `config_enabled` `override_disabled` `path_removed` `no_probe_link` `config_error` `mon_client_offline` `mon_client_disabled` `mon_client_revoked` `derived`; для `mon_client` — `heartbeat_missed`, `token_revoked`). Причины `PAUSED` у inbound (`config_disabled`) и у конфига mon-client (`override_disabled` `path_removed` `no_probe_link` `config_error`) снимаются каждая своей стороной: включение inbound'а не снимает паузу `path_removed`.

**Derived state** (решение [#100](https://github.com/SBKubric/3ax-ui-monitoring/issues/100), [CONTEXT.md](../../CONTEXT.md)) — у target'а `inner:*`, который mon-client держит без проб (§5.1): после живого цикла каждого heartbeat он переходит в `UP`, если хоть один edge-path (`edge:*`) того же `inboundKind` у этого mon-client в `UP` — edge-path идёт через это звено; иначе остаётся как есть (его состояние решит diagnostic sweep). Переход — событие `{kind: target, …, reason: derived, notified: true}`: панель пишет его на страницу и в ленту, Telegram нет ни от панели, ни от mon-server (и в `PANEL_DOWN`). `PAUSED` и уже `UP` не трогаются; `direct` derived state не имеет. Строка такого target'а создаётся `UNKNOWN` без события; `OFFLINE`/Disable/Revoke переводят её в `UNKNOWN`, как любую. Target, бывший `PAUSED path_removed` и ставший удерживаемым без проб (переход коробки на `edges`), освобождается в `UNKNOWN` (`config_enabled`).

**Сверка состояния** (state resync, решение [SBKubric/sane-3x-ui#151](https://github.com/SBKubric/sane-3x-ui/issues/151)) — единственное событие target'а без перехода. Панель в ответе `POST /stats` перечисляет в необязательном поле `resync` target'ы, по которым у неё нет состояния (`[{monClientId, inboundKind, inboundId, path}]`; старая панель поле не шлёт). На каждый названный target, который mon-server знает и держит не в `UNKNOWN`, в outbox уходит событие `{kind: target, from = to = текущее состояние, reason: resync, notified: true}` со свежим `id` и `ts` = время mon-server сейчас (не `since` target'а: панель не применяет событие старше `since` своей строки, а пересозданная строка новее состояния mon-server). Target в `UNKNOWN` или неизвестный — ничего. Не чаще раза на target за цикл статистики (5-минутное окно, чьё закрытие отправляется); ограничение в памяти, после рестарта сверка может повториться. Telegram нет, строка `targets` не меняется.

### 7.3 mon-client

`OFFLINE` после `clientOfflineAfter` (3) пропущенных heartbeat подряд по времени приёма (проверяет job раз в 20 с: `now − max(last_heartbeat, serverReadyAt) > 3 × intervalMs + heartbeatTimeoutMs`); все его targets → `UNKNOWN` (события с `reason: mon_client_offline`, без Telegram); событие `mon_client OFFLINE` (`reason: heartbeat_missed`) → Telegram через панель («mon-client <name> (<region>) OFFLINE»). `ONLINE` — первый heartbeat, все targets остаются `UNKNOWN` до результата.

**Рестарт mon-server** (решение [#84](https://github.com/SBKubric/3ax-ui-monitoring/issues/84)): тишина считается от `max(last_heartbeat, serverReadyAt)`, где `serverReadyAt` — момент, когда HTTPS-listener начал принимать соединения (после загрузки или выпуска ACME-сертификата; в режиме `files` — сразу после bind), а не старт процесса; до него job не запускается. Heartbeat'ы, пропущенные, пока лежал сам mon-server, не засчитываются: после простоя любой длины — ни `OFFLINE`, ни `ONLINE`-перехода; mon-client, умерший во время простоя, получает `OFFLINE` через `clientOfflineAfter` интервалов после `serverReadyAt`. О своём простое mon-server пишет только строку в лог в момент `serverReadyAt` — `started; last heartbeat seen <d> ago` (по самому свежему `last_heartbeat`; строки нет, если heartbeat'ов ещё не было); событий и Telegram нет — это закрывают STALE и «monitoring back» на панели. Остальное рестарт не затрагивает: `panelDownAfter` считает опросы, которые идут только у работающего сервера, а state machine targets меняется только живыми циклами.

**Revoke** — тот же переход по решению администратора (решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 2): событие `mon_client → OFFLINE` с `reason: token_revoked`, targets → `UNKNOWN` с `reason: mon_client_revoked`, Telegram по тем же правилам, что у `OFFLINE` по таймауту (через панель; в `PANEL_DOWN` — сам mon-server). Уже `OFFLINE` mon-client второго перехода не получает. `PAUSED` targets, как и при `OFFLINE`/Disable, остаются `PAUSED`.

### 7.4 Статистика

Бакет 5 мин по `(monClientId, inboundKind, inboundId, path, bucketStart = ts − ts % 300000)`: `n_ok`, `n_fail` (unverified-провалы не считаются), `lat_min/avg/max` по `tlsMs` успешных проб, `handshake_ms` — `handshakeMs` последнего успешного цикла бакета (только AWG), `NULL` при `n_ok=0`. Бакет закрывается через 1 мин после конца окна и уходит в `POST /stats` (§4 шаг 4); досланные циклы дописывают в бакет и, если он уже отправлен, отправляют повторно (upsert на панели).

### 7.5 Tunnel probe

`GET /v1/probe?target=<kind:inboundId:path>&n=<nonce>` с client token (ключ делится по `:` не больше чем на 3 части — path сам может содержать `:`, протокол §5.2): ответ `200 {nonce, egressIp: <source IP запроса>, serverTs}`; запись в `probe_seen`. Состояние по этим запросам **не** считается: успех определяет mon-client в heartbeat. Неизвестный target для этого mon-client — `200` всё равно (диагностика), запись помечается `unknown_target`.

## 8. Telegram от mon-server

Бот и chat id — в настройках (§9.4), тот же бот, что у панели. mon-server шлёт сам только: «panel unreachable» / «panel back, N событий дослано»; переходы в режиме `PANEL_DOWN` с пометкой «via mon-server»; `configError` mon-client («mon-client <name>: config error <первая строка>»); `404` на `GET /state` («panel rejects monitoring token or monitoring is disabled»). Всё остальное — через панель (контракт §4.6, `notified=false`).

## 9. Admin UI

Решения тикета [Admin UI mon-server: страницы заявок, реестра и настроек](https://github.com/SBKubric/3ax-ui-proxy/issues/37): вариант A прототипа ([артефакт](https://claude.ai/code/artifact/4b51c48d-1c19-4acb-b7cc-798ac9816f31), [исходник](https://github.com/SBKubric/3ax-ui-proxy/blob/prototype/mon-admin-ui/docs/prototypes/mon-admin-ui.html)) — оболочка панели 3AX-UI: тёмный сайдбар, карточки, таблицы, по странице на задачу.

### 9.1 Стек и auth

- **Vue 3 + Ant Design Vue 4 без сборщика**: UMD-сборки `vue.global.prod.js`, `antd.min.js`, `antd.min.css` (+ `dayjs`) лежат в `web/assets/` и вшиваются в бинарник `go:embed`; страницы — `html/template`, по одному Vue-приложению на страницу, без роутера. Тема через `ConfigProvider` (`colorPrimary #008771`, `darkAlgorithm` по переключателю, хранится в `localStorage`). Node в сборке не нужен. Только английский в v1, строки в одном объекте `strings` на страницу.
- Логин: **логин + пароль**, bcrypt (`admin set`), cookie-сессия `mon_session` (HttpOnly, Secure, SameSite=Lax) на 24 ч; 5 неудачных логинов с IP → 15 мин блокировки (`login_attempts`); без 2FA. Все `/admin/*`, кроме `/admin/login`, требуют сессию; JSON-ручки admin UI живут под `/admin/api/*` и отдают `{success, msg, obj}` как панель.

### 9.2 Requests (`/admin/requests`)

Пункт меню с бейджем числа pending. Таблица: IP · hostname (+ версия, номер попытки) · pairing code крупным моноширинным · «expires mm:ss / received N ago» · Operate: **Approve**, **Approve as replacement ▾**, **Reject**; в шапке rate-limit'ы. Строка подсвечена, если hostname или IP совпадают с существующим mon-client («same hostname as msk-1: replacement?»).

**Approve** — модалка: код крупно + предупреждение «сверьте с логом коробки», переключатель «New mon-client / Replace an existing one», Name + Region (id = slug имени показан под полем, постоянный), выбор paths (§5.1): чекбоксы `direct`, `edges` и `hops` (по умолчанию отмечен только `edges`), со снятым `hops` — явные звенья из последнего `GET /state` (`edge:<name>` / `inner:<name>`, пробируемые); пояснение, что `direct` раскрывает адрес real server этой коробке, а inner доступен не из каждого региона. В режиме замены — выбор существующей записи (name/region/paths берутся из неё). Кнопка «Approve and issue token».

### 9.3 mon-clients (`/admin/clients`)

Таблица в стиле inbound'ов панели: Operate «⋯» (Edit, Revoke, Delete) · switch Enabled · Name с id·region · State (`ONLINE`/`OFFLINE`/`never seen`/`disabled`) · Last heartbeat («approved N ago» для never seen) · Paths тегами (как в `paths`: `direct`, `edges`, `hops`, явные звенья) · Version (mon-client + xray) · Config (применённая ревизия или тег ⚠ config error с тултипом; тег «⚠ N rejected», если mon-client отверг targets ревизии; тег «⚠ N no peer», если панель не выдала AWG probe-пиров). Над таблицей — фильтр по path: `direct` или звено из последнего `GET /state`; остаются mon-clients, чьи paths в него раскрываются (`hops` совпадает с любым звеном, `edges` — с любым edge). **Edit** — модалка: name, region, paths (тот же выбор, что в Approve) правятся, id — нет; там же полный текст configError, отвергнутые targets таблицей inbound · path · ошибка (`rejectedTargets` последнего heartbeat), AWG-targets в `PAUSED no_probe_link` таблицей path · причина (`pool_exhausted` — кончился пул адресов AWG-сервера, `limit` — превышен `monProbePeerLimit` панели; из `mon_clients.unallocated`), применённая и серверная ревизии. **Revoke** — confirm с пояснением (401 → коробка стирает state и подаёт новую заявку; одобрить её как replacement). Состояние targets и агрегаты по звену не показываются (§5.1).

### 9.4 Settings (`/admin/settings`)

Одна кнопка **Save** сверху, строка статуса «Panel reachable · revision · N inbounds · override → host · chain: N probed hops, active edge <name> · checked N ago» (часть про цепочку — только если она есть) (или последняя ошибка; если последний запрос упал на `x509: unknown authority` — отдельный текст с подсказкой про `panelCa`). Табы:

| таб | поля (ключ `settings`) |
|---|---|
| **Real server** | `panelUrl` (base URL панели с `webBasePath`), `monToken`, `panelCa` (textarea, PEM-цепочка; задана → запросы к панели доверяют **только** этому пулу вместо системного, самоподписанный лист панели годится как trust anchor; пусто → системный пул; невалидный PEM отклоняется при Save и Check), кнопка **Check** (`GET /state` и `GET /probe/configs` для введённого `realHost` по введённым значениям, включая `panelCa`, без Save; `x509: unknown authority` — отдельный текст с подсказкой про `panelCa`; панель с `contract` ≠ 3 — ошибка `contract` с текстом `panel speaks monitoring contract N, mon-server needs 3 — update the panel` (или `… — update mon-server`), тот же текст показывает строка статуса, пока poll отказывается), `realHost` — адрес для path `direct`, по умолчанию host из `panelUrl`; **read-only блок Proxy front**: override вкл/выкл и host, с цепочкой — звенья (name, role, state, active) из последнего `GET /state` — своего поля proxy front у mon-server нет |
| **Telegram** | `tgToken`, `tgChatId`, кнопка **Send test** (без Save) |
| **Thresholds** | `downAfter 3`, `upAfter 2`, `flapN 4`, `flapMin 30`, `flapHoldMin 15`, `clientOfflineAfter 3`, `panelDownAfter 3` |
| **Probe** | `intervalMs 60000`, `budgetMs 20000`, `connectMs 5000`, `tlsMs 10000`, `headersMs 10000`, `startJitterMs 5000`, `heartbeatTimeoutMs 10000` |
| **TLS & admin** | read-only из bootstrap: `tls.mode`, в `acme-ip` — CA (`tls.acmeCa` и URL directory), срок сертификата и следующее продление, `dataDir`, `listen`; подсказка `mon-server admin set <user>` |

Save применяет всё разом; смена `probe`-параметров пересобирает `client_configs` всем mon-clients (новая config revision). Смена `realHost` или `panelUrl` (решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 4) сбрасывает кэш probe-материала и сразу перечитывает `GET /state` + `GET /probe/configs` (§4 шаг 3) с сохранёнными значениями, затем пересобирает `client_configs` (ссылки входят в хэш — ревизия меняется); панель недоступна → Save всё равно сохраняет, кэш остаётся сброшенным, и материал перечитывает следующий poll. **Check** делает то же на лету без сохранения: после `GET /state` — `GET /probe/configs?host=<введённый realHost или host из panelUrl>` и, с цепочкой, `GET /probe/configs?hop=<name>` на каждое пробируемое звено (без цепочки — `GET /probe/configs` при включённом override); показывает число probe-ссылок по каждому path (или ошибку панели), кэш материала и `client_configs` не трогает.

## 10. Ручки (сводка)

| путь | кто | auth |
|---|---|---|
| `POST /v1/register`, `GET /v1/register/<requestId>` | mon-client | rate limit / `requestId` |
| `GET /v1/config`, `POST /v1/heartbeat` | mon-client | client token |
| `GET /v1/probe?target=&n=` | mon-client, через туннель | client token |
| `GET /healthz` | кто угодно | нет |
| `/admin/login`, `/admin/logout` | администратор | логин + пароль |
| `/admin/requests`, `/admin/clients`, `/admin/settings` (страницы) и `/admin/api/*` (JSON) | администратор | cookie-сессия |

Панель mon-server вызывает сам (§4); внешних входящих от панели нет.

## 11. Структура кода

```
cmd/mon-server/main.go        — CLI: run, admin set, version
internal/config/              — bootstrap-конфиг (файл/ENV)
internal/store/               — GORM-модели §3, миграции, ретеншн
internal/panel/               — клиент контракта, poll, outbox, PANEL_DOWN
internal/registry/            — заявки, токены, mon-clients, config revision
internal/state/               — state machine targets и mon-clients, бакеты
internal/api/                 — /v1/* хендлеры
internal/admin/               — /admin/* хендлеры, сессии, login_attempts
internal/tg/                  — Telegram
internal/tlsx/                — certmagic / files
web/assets/, web/html/        — admin UI (go:embed)
docs/spec/                    — эта спека, протокол, mon-client
```

## 12. План реализации

Каждый шаг — отдельный коммит; тесты `go test ./...`; интеграция с панелью — httptest-стаб контракта.

1. Bootstrap-конфиг, `store` с моделями §3, `admin set`; тесты миграции и bcrypt.
2. TLS (`certmagic` в `acme-ip`, `files`), листенер, `/healthz`.
3. Клиент панели §4: `GET /state`, ревизия, `POST /probe/ensure`, `GET /probe/configs`; тесты на стабе: смена ревизии перечитывает конфиги, `404` → Telegram, 3 неудачи → `PANEL_DOWN`, возврат досылает outbox.
4. Регистрация §6: `/v1/register*`, rate limit, TTL заявок, одобрение/замена/отклонение, токены; тесты на лимиты, одноразовую выдачу токена, replacement.
5. Конфиг per-client и config revision §5; тесты детерминированности хэша и его изменения от paths/probe/realHost.
6. Heartbeat §7.1 и state machine §7.2–7.3; таблица тестов на все переходы, unverified-правило, досылку, кламп времени, `ackSeq`.
7. Статистика §7.4 и отправка `POST /events`/`POST /stats` §4 шаг 4; тесты на закрытие бакетов и повторную отправку.
8. Tunnel probe §7.5 и `probe_seen`.
9. Telegram §8.
10. Admin UI §9: логин и сессии, Requests, mon-clients, Settings (Check, Send test, Save с пересборкой конфигов); embed-ассеты.
11. Ретеншн-job §3, `version`, README с установкой (упаковка mon-server — туман карты, не решалось).
12. Ручная проверка на стенде: панель на real server + proxy front + два mon-client → заявки, одобрение, `UP` по обоим path, `DOWN` при остановке inbound'а, `PANEL_DOWN` при остановке панели.
13. Per-hop ([#61](https://github.com/SBKubric/3ax-ui-monitoring/issues/61)): контракт 3 (строгая проверка `== 3`, `chain`, `?hop=`, `paths` в снимке ensure, `unallocated` с `reason`), paths по цепочке и словарь `paths` с миграцией `proxy` → `hops` §5.1, молчаливое удаление targets ушедшего звена, разбор ключа target'а на 3 части, admin UI §9.2–9.4; тесты на раскрытие `hops`, переключение active edge без смены config revision, удаление и переименование звена без событий.
