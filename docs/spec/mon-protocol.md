# Протокол mon-server ↔ mon-client (v1)

Статус: **принят** — итог карты [Healthcheck-мониторинг inbound'ов: mon-server, mon-clients и контракт с панелью](https://github.com/SBKubric/3ax-ui-proxy/issues/20); черновик принят в тикете [Протокол mon-server ↔ mon-client: регистрация, heartbeat, ревизия, targets](https://github.com/SBKubric/3ax-ui-proxy/issues/27), собран в [Собрать спеку](https://github.com/SBKubric/3ax-ui-proxy/issues/29). Термины — по [CONTEXT.md](../../CONTEXT.md) (mon-server, mon-client, target, path, probe account, tunnel probe, heartbeat, registration request, pairing code, client token, config revision, unverified cycle, admin UI). Панельная сторона — [Контракт API панели для mon-server](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/spec/monitoring-contract.md) в репо `3ax-ui-proxy`; состояния и пороги — [State machine target'а](https://github.com/SBKubric/3ax-ui-proxy/issues/22); механика проб — [research mon-client probes](https://github.com/SBKubric/3ax-ui-proxy/blob/research/mon-client-probes/docs/research/mon-client-probes.md). Реализация сторон — [mon-server.md](mon-server.md) и [mon-client.md](mon-client.md).

Все запросы инициирует mon-client; mon-server к mon-client не ходит (коробка может быть за NAT).

## 1. Транспорт и TLS

- HTTPS на одном листенере mon-server (`:443` по умолчанию); heartbeat, регистрация и конфиг идут **мимо** туннеля, tunnel probe — **через** туннель target'а; различаются путями, а не портами.
- Сертификат — Let's Encrypt для **IP-адреса**: профиль `shortlived` (160 ч), challenge `tls-alpn-01` на том же `:443`, `:80` не нужен, домена не нужно. В mon-server встроен certmagic (`Profile: "shortlived"`, `DisableHTTPChallenge: true`, `RenewalWindowRatio ≈ 0.5` → продление каждые ~3 дня, сертификаты в `dataDir`). `:443` должен быть открыт всему интернету (валидаторы LE), на коробке mon-server нужен NTP. Режимы: `tls.mode = acme-ip` (default) | `files` (свой cert/key: домен или тесты).
- mon-client проверяет сертификат системными CA; пиннинга нет.
- JSON, `Content-Type: application/json`; времена — `int64` ms epoch; ошибки — HTTP-статус + `{error, message}` как в контракте панели.

## 2. Регистрация

### 2.1 Заявка

mon-client стартует с одним параметром — `serverUrl`. Без сохранённого client token он подаёт registration request:

```http
POST /v1/register
{"pairingCode": "7K3F9Q", "hostname": "vps-ams-1", "version": "0.1.0", "publicIp": "203.0.113.5"}
```

- `pairingCode` — 6 символов `[A-Z2-9]`, генерирует mon-client, печатает в лог/консоль при каждой заявке.
- Ответ `202 {"requestId": "<128 бит, base64url>", "pollAfter": 10000, "expiresAt": <ms>}`. `requestId` — секрет опроса.
- Заявка живёт **5 минут**; по истечении — `410 request_expired`, mon-client подаёт новую (новый код) с backoff 1 → 2 → 5 мин, дальше каждые 5 мин.
- Rate limit: 1 заявка на IP в минуту, не больше 3 pending с одного IP, не больше 20 pending глобально (`429 too_many_requests`, `Retry-After`). Неверный/чужой `requestId` — `404` без деталей.

### 2.2 Опрос и одобрение

```http
GET /v1/register/<requestId>
→ 200 {"status": "pending"}
→ 200 {"status": "approved", "monClientId": "ams-1", "token": "<client token>"}
→ 200 {"status": "rejected"}   (mon-client ждёт 1 ч и подаёт новую заявку)
→ 410 request_expired
```

- В admin UI администратор видит IP, hostname, версию и pairing code, сверяет код с логом коробки, вводит `name` и `region`, выбирает paths и жмёт **Approve** — либо **Approve as replacement** для существующего mon-client (id, история, paths сохраняются, старый client token отзывается). `monClientId` — slug из `name` (`ams-1`), уникален, ≤ 32 символов `[A-Za-z0-9_-]` (из него панель называет AWG probe-пиры, решение [#80](https://github.com/SBKubric/3ax-ui-monitoring/issues/80)).
- Одобренная заявка отдаёт `token` один раз; mon-client сохраняет `monClientId` + `token` в state-файл (`/var/lib/mon-client/state.json`, 0600) и больше `/register` не зовёт.
- Запись реестра появляется при одобрении в состоянии `ONLINE`/`OFFLINE` по первому heartbeat (до него — `never seen`).

### 2.3 Отзыв

**Revoke** в admin UI → client token недействителен (mon-server проводит это через state machine: событие `mon_client → OFFLINE` с `reason: token_revoked`, targets → `UNKNOWN`) → heartbeat получает `401 token_revoked` → mon-client останавливает пробы, стирает state-файл и подаёт новую заявку по правилам 2.1. Удалённый mon-client уходит из снимка реестра (`POST /probe/ensure` панели), панель чистит его строки `mon_targets`.

## 3. Аутентификация после регистрации

`Authorization: Bearer <client token>` на всех ручках, кроме `/v1/register*`. Токен — 32 случайных байта, хранится на mon-server хэшем (SHA-256), сравнение constant-time. `401` — токен неизвестен/отозван (см. 2.3); `403` — токен известен, но mon-client `disabled` в admin UI (mon-client ждёт и повторяет heartbeat раз в 5 мин, проб не гоняет).

## 4. Конфиг mon-client

### 4.1 Ревизия

**Config revision** — первые 16 hex SHA-256 от канонического JSON документа §4.2 без поля `configRevision`. Меняется, когда меняется материал панели для этого mon-client (по ревизии панели `GET /state`, куда с контракта 3 входит и цепочка), его paths, `probe`-параметры или `probeUrl`; смена ревизии панели, не задевшая материал (переключение active edge), config revision не двигает. Считается per-mon-client; ревизия панели наружу не транслируется.

### 4.2 `GET /v1/config`

```json
{
  "configRevision": "3a91c0de77b1f2e4",
  "monClientId": "ams-1",
  "probeUrl": "https://203.0.113.10:443/v1/probe",
  "probe": {"intervalMs": 60000, "budgetMs": 20000, "connectMs": 5000, "tlsMs": 10000, "headersMs": 10000, "startJitterMs": 5000, "heartbeatTimeoutMs": 10000},
  "targets": [
    {"inboundKind": "xray", "inboundId": 12, "path": "edge:ams-1",   "protocol": "vless", "link": "vless://…@198.51.100.20:443?security=reality&…#probe-12"},
    {"inboundKind": "xray", "inboundId": 12, "path": "inner:core-1", "protocol": "vless", "link": "vless://…@198.51.100.7:443?security=reality&…#probe-12"},
    {"inboundKind": "xray", "inboundId": 12, "path": "direct",       "protocol": "vless", "link": "vless://…@203.0.113.10:443?…#probe-12"},
    {"inboundKind": "awg",  "inboundId": 0,  "path": "edge:ams-1",   "protocol": "awg",   "conf": "[Interface]\n…\n[Peer]\nEndpoint = 198.51.100.20:51820\n…"}
  ]
}
```

- mon-server собирает `targets` как `items` из `GET /probe/configs?host=<real>` (path `direct`) и `GET /probe/configs?hop=<name>` на каждое пробируемое звено цепочки (path `edge:<name>` / `inner:<name>`; на панели без цепочки — `GET /probe/configs`, path `proxy`, только при `override.enabled`) × `paths` этого mon-client (словарь `direct` | `edges` | `hops` | явные звенья, default `[edges]` — только edge-path'ы, остальные path'ы цепочки mon-server держит без проб, решение [#100](https://github.com/SBKubric/3ax-ui-monitoring/issues/100); для коробок во враждебных регионах владелец снимает `direct`, чтобы не светить настоящий адрес real server как Reality-endpoint) — [mon-server.md](mon-server.md) §5.1, решение [#61](https://github.com/SBKubric/3ax-ui-monitoring/issues/61). Все inbound'ы — всем mon-clients; фильтра по inbound'ам в v1 нет. xray-ссылки общие, а AWG `.conf` у каждого mon-client свой (решение [#80](https://github.com/SBKubric/3ax-ui-monitoring/issues/80)): панель держит AWG probe-пир на mon-client × path, на котором этот mon-client держит target (`paths` едут в снимке ensure; `edges` — как весь набор path цепочки), и mon-client получает только свой; wire-форма target'а от этого не меняется. Нет своего пира — нет AWG-target'а в конфиге (у mon-server он `PAUSED no_probe_link`).
- **`sweepTargets`** (решение [#100](https://github.com/SBKubric/3ax-ui-monitoring/issues/100), необязательное поле той же формы, что `targets`): targets, которые mon-server держит без проб каждый цикл (`direct` и `inner:*` у mon-client на `edges`), с их материалом. mon-client применяет их вместе с ревизией (xray-outbound и socks-порт в `xray.json`, разбор `.conf`; битый — в `rejectedTargets`, как любой), но пробирует только в цикле с diagnostic sweep (§5.3), — так обход не требует новой ревизии и рестарта xray. Нет таких targets — поля нет; старый mon-client поле игнорирует.
- **Грамматика `path`**: `direct` | `proxy` | `edge:<name>` | `inner:<name>`, `<name>` — имя звена цепочки (`[a-z0-9-]{1,32}`); `proxy` приходит только от панели без цепочки. Поведение mon-client от path не зависит: он только проверяет грамматику и возвращает path в результатах и ключах target'а (§5.2, §5.3). Кроме допустимых значений path, протокол не меняется и остаётся v1; дизайн mon-client тоже (решение [#61](https://github.com/SBKubric/3ax-ui-monitoring/issues/61) п. 8).
- `link`/`conf` отдаются **как есть**: mon-server прозрачен, знание протоколов (ссылка → xray-outbound, .conf → netstack-устройство) живёт только в mon-client. Выключенных inbound'ов в `targets` нет — mon-server сам держит их как `PAUSED`.
- `probe`-параметры — из research: цикл 60 с, бюджет пробы 20 с, connect 5 с, TLS 10 с, заголовки 10 с, джиттер старта 0–5 с, heartbeat 10 с. Настраиваются в admin UI глобально; пороги state machine (3/2/4-за-30/15) mon-client не нужны и в конфиг не входят.

### 4.3 Применение

- Ответ heartbeat несёт `configRevision`; отличается от применённой → mon-client делает `GET /v1/config` (тот же путь, что при старте и после потери state).
- Применение — **между циклами**: пробы в полёте дожидаются, генерируется новый xray-конфиг (все xray-targets в одном процессе: socks-inbound на target + outbound + правило routing), `xray -test`, рестарт дочернего xray; netstack-устройства AWG и так пересоздаются на пробу. Первый цикл после применения — обычный, грейса нет: результаты по удалённым targets отбрасываются, новые targets стартуют у mon-server с `UNKNOWN`.
- Применение **поцелевое** (решение [#53](https://github.com/SBKubric/3ax-ui-monitoring/issues/53) п. 3): target, чья ссылка или `.conf` не разбирается либо чей AWG-конфиг не принимает пробный `IpcSet`, отвергается, остальные применяются, ревизия считается применённой (даже если отвергнуты все). Отвергнутые идут в heartbeat как `client.rejectedTargets` (§5.3); mon-server переводит их в `PAUSED` с `reason: config_error` (событие панели, Telegram нет), а target, пропавший из `rejectedTargets`, — в `UNKNOWN`.
- Ревизия не применилась целиком (`xray -test` упал, xray не перезапустился) → mon-client остаётся на старой ревизии, шлёт `configError` в heartbeat; mon-server пишет ошибку в реестр (видна в admin UI) и шлёт Telegram сам. Контракт панели не расширяется.

## 5. Цикл проб и heartbeat

### 5.1 Цикл

Раз в 60 с (по `intervalMs`, старт со случайным джиттером): все targets параллельно, каждая проба — `GET probeUrl` через свой туннель с бюджетом 20 с; затем один heartbeat с результатами цикла. Успех пробы определяет **mon-client**: `200` + совпавший `nonce` в бюджете.

### 5.2 Tunnel probe (через туннель)

```http
GET /v1/probe?target=xray:12:edge:ams-1&n=<nonce>
Authorization: Bearer <client token>
→ 200 {"nonce": "<тот же>", "egressIp": "162.159.x.x", "serverTs": 1757721600000}
```

- **Ключ target'а** — `<kind>:<inboundId>:<path>`; path может сам содержать `:` (`edge:ams-1`), поэтому обе стороны делят ключ по `:` не больше чем на 3 части (`strings.SplitN(key, ":", 3)`) и проверяют третью часть по грамматике path (§4.2), а не по белому списку `direct`/`proxy`. Тот же ключ — в `client.rejectedTargets` (§5.3).
- Ключ target'а и токен едут в запросе, потому что source IP пробы — real server или его WARP-egress и target'а не выдаёт.
- mon-server по этим запросам **состояние не считает**, только логирует «seen» (`monClientId`, target, `egressIp`, время) как диагностику и защиту от расхождений с heartbeat; в панель это не идёт.
- Через xray-туннель проба ходит `Transport.Proxy = socks5://127.0.0.1:<port target'а>`; через AWG — `tnet.DialContext` netstack-устройства. Тайминги — `httptrace` по research §6.

### 5.3 Heartbeat (мимо туннеля)

```http
POST /v1/heartbeat
{
  "monClientId": "ams-1", "configRevision": "3a91c0de77b1f2e4",
  "client": {"version": "0.1.0", "xrayVersion": "26.3.27", "uptimeMs": 86400000, "configError": null},
  "cycles": [
    {"seq": 1441, "ts": 1757721600000, "unverified": false, "results": [
      {"inboundKind": "xray", "inboundId": 12, "path": "edge:ams-1", "ok": true,
       "connectMs": 3, "tlsMs": 47, "ttfbMs": 39, "handshakeMs": null, "egressIp": "203.0.113.10", "reason": null, "detail": null},
      {"inboundKind": "awg", "inboundId": 0, "path": "edge:ams-1", "ok": false,
       "connectMs": null, "tlsMs": null, "ttfbMs": null, "handshakeMs": null, "egressIp": null,
       "reason": "awg_no_handshake", "detail": "last_handshake_time=0 after 20000ms"}
    ]}
  ]
}
→ 200 {"configRevision": "3a91c0de77b1f2e4", "serverTs": 1757721620000, "ackSeq": 1441}
```

- **Diagnostic sweep** (решение [#100](https://github.com/SBKubric/3ax-ui-monitoring/issues/100), необязательные поля): ответ heartbeat может нести `"sweep": {"kinds": ["awg"], "hosts": [{"name": "proxy", "host": "198.51.100.20"}, {"name": "", "host": "203.0.113.10"}]}` — задание на **следующий** цикл: пробировать `sweepTargets` этих `inboundKind` (параллельно с обычными targets, с теми же бюджетами) и проверить каждый `host` серией ICMP-эхо (host reachability check: 10 эхо через ~200 мс, ожидание ответов ~1 с; `name` — имя звена, `""` — real server, `proxy` — proxy front панели без цепочки). Один ответ — один обход; следующий mon-server попросит сам. Цикл с обходом несёт его результат в необязательном поле `sweep`:
  ```json
  {"seq": 1442, "ts": 1757721660000, "unverified": false, "results": [...],
   "sweep": {"kinds": ["awg"],
             "results": [{"inboundKind": "awg", "inboundId": 0, "path": "direct", "ok": true, …}],
             "hosts": [{"name": "proxy", "sent": 10, "lossPct": 0, "rttAvgMs": 2, "reason": null},
                       {"name": "", "sent": 0, "lossPct": 0, "rttAvgMs": null, "reason": "icmp_unavailable"}]}}
  ```
  `results` — той же формы, что у цикла, только по `sweepTargets`; в state machine и статистику они не идут. `hosts[].reason` — серия не выполнялась: `icmp_unavailable` (нет непривилегированного ICMP-сокета, `net.ipv4.ping_group_range` не включает группу mon-client) или `resolve_failed` (имя не резолвится в IPv4); это «не измерено», а не 100% потерь. `rttAvgMs` — `null`, если ответов не было. mon-server берёт обход только из живого цикла и только тот, о котором просил.
- `client.rejectedTargets` — `[{"target": "<kind>:<inboundId>:<path>", "error": "<первая строка, ≤ 256>"}]`: targets применённой ревизии, которые mon-client отверг при применении (§4.3) и не пробует. Поле отсутствует или пусто — применено всё. `configError` остаётся для ошибок ревизии целиком и упавшего xray. Ключ делится на 3 части (§5.2). Пример: `"rejectedTargets": [{"target": "awg:3:direct", "error": "[Interface] has an unknown key \"Foo\""}]`.
- `reason` — словарь диагностики контракта панели §4.6 (`tcp_refused` `tcp_timeout` `tls_timeout` `reality_real_cert` `awg_no_handshake` `http_error` …); `detail` — ≤ 256 символов, последняя строка xray-лога с тем же session-id или текст ошибки; в панель `detail` не уходит.
- Латентность для xray — фаза TLS (`tlsMs`), `ttfbMs` — RTT, `handshakeMs` — только AWG (`last_handshake_time − t(dial)`); в 5-мин бакет панели mon-server кладёт `min/avg/max` по `tlsMs` и `handshakeMs` последнего успешного цикла бакета.
- **Время**: mon-server ставит своё время приёма для состояния target'ов и heartbeat; `ts` цикла используется только для раскладки по 5-мин бакетам и клампится к времени приёма при расхождении > 5 мин.
- **Буфер**: heartbeat не подтверждён (сеть, 5xx, таймаут) → цикл остаётся в буфере (≤ 60 циклов, старые вытесняются) и досылается в следующем heartbeat вместе с новыми; `ackSeq` подтверждает всё до него включительно. Досланные циклы идут **только в статистику**; состояние target'ов mon-server считает по циклам, пришедшим своим heartbeat'ом (переходы задним числом не переигрываются).
- **Seq** (решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 1) привязан к поколению client token: mon-server сбрасывает свой `last_ack_seq` в 0 при каждой выдаче токена (одобрение, одобрение как replacement), mon-client начинает с `seq=1` при каждой новой регистрации. Внутри поколения seq монотонен: mon-client хранит счётчик в `cycles.json`, а последний полученный `ackSeq` — в `state.json` (`lastAckSeq`). Потерян или повреждён `cycles.json` → следующий seq = `lastAckSeq + 1`, не 1 (перерегистрация не нужна); `ackSeq` в ответе выше собственного счётчика (потеряны оба файла) → следующий цикл идёт с `ackSeq + 1`.
- **Unverified cycle**: цикл, за который heartbeat не был подтверждён, помечается `unverified: true`. Адресат tunnel probe — сам mon-server, поэтому его недоступность неотличима от падения туннеля: из unverified-циклов в статистику берутся только успехи, провалы считаются пропуском (`null`, не `nFail`).
- mon-client `OFFLINE` у mon-server — 3 пропущенных heartbeat подряд (по времени приёма), `ONLINE` — первый heartbeat; правила из State machine.

## 6. Что mon-server делает с результатами

1. По heartbeat: обновляет `lastHeartbeat`/`ONLINE`, применяет результаты живого цикла к state machine target'ов (`UP`/`DOWN`/`FLAPPING`/`UNKNOWN`/`PAUSED`), формирует события `POST /events` панели с `reason` из результата, кладёт результаты всех циклов в 5-мин бакеты `POST /stats`.
2. Раз в минуту: `GET /state` панели → при смене ревизии панели пересобирает конфиги всех mon-clients (новая config revision у каждого), `POST /probe/ensure` со снимком реестра (`id`, `name`, `region`, `state`, `lastHeartbeat`, `paths`).
3. `PANEL_DOWN` — по контракту §7: события копятся, Telegram шлёт mon-server, poll продолжается.

## 7. mon-server: хранилище, admin UI, bootstrap

- **Хранилище** — SQLite одним файлом в `dataDir` (GORM, как у панели): настройки, реестр mon-clients (id, name, region, paths, token-hash, enabled, lastHeartbeat, configError, rejectedTargets), pending registration requests, состояние targets, буфер событий при `PANEL_DOWN`, бакеты до отправки.
- **Bootstrap-конфиг** (файл/ENV) минимален: `listen` (`:443`), `publicIp` (для ACME), `dataDir`, `tls.mode`. Всё остальное — в admin UI: адрес панели и `monToken`, настоящий адрес real server (`host` для path `direct`), Telegram-бот и chat id, пороги state machine, `probe`-параметры, paths и enable per-mon-client.
- **Admin UI**: один администратор, логин и пароль (bcrypt) задаются `mon-server admin set <user>`; cookie-сессия 24 ч; 5 неудачных логинов → 15 мин блокировки по IP; без 2FA в v1. Страницы: логин, pending-заявки (Approve / Approve as replacement / Reject), реестр mon-clients (state, last heartbeat, paths, configError; Revoke, Disable), настройки. Состояние targets admin UI **не показывает** — единственная картина мониторинга остаётся страницей Monitoring панели. Страницы и поля — [mon-server.md](mon-server.md) §9 (решено в тикете [Admin UI mon-server](https://github.com/SBKubric/3ax-ui-proxy/issues/37)).
- Регистрация и tunnel probe — свои токены (§2, §3); всё остальное в UI — за сессией.

## 8. Ручки (сводка)

| метод и путь | кто | через туннель | auth |
|---|---|---|---|
| `POST /v1/register` | mon-client без токена | нет | rate limit, без auth |
| `GET /v1/register/<requestId>` | mon-client | нет | `requestId` |
| `GET /v1/config` | mon-client | нет | client token |
| `POST /v1/heartbeat` | mon-client, раз в минуту | нет | client token |
| `GET /v1/probe?target=&n=` | mon-client, раз в минуту на target | **да** | client token |
| `/admin/*` | администратор | нет | cookie-сессия |

## 9. Пример жизни mon-client

1. Старт без state-файла: `POST /v1/register` → код в логе → опрос до `approved` → state-файл.
2. `GET /v1/config` → xray-конфиг, `xray -test`, запуск xray.
3. Каждые 60 с: пробы → heartbeat → `configRevision` совпала → следующий цикл. Не совпала → `GET /v1/config` → применить между циклами.
4. Heartbeat не прошёл → цикл в буфер как unverified, пробы продолжаются, досылка при первом успехе.
5. `401` → стереть state-файл → шаг 1.
