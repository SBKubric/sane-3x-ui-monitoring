# mon-client

Спека и план реализации. Итог карты [Healthcheck-мониторинг inbound'ов: mon-server, mon-clients и контракт с панелью](https://github.com/SBKubric/3ax-ui-proxy/issues/20); решения приняты в её тикетах, здесь они только собраны. Термины по [CONTEXT.md](../../CONTEXT.md). Wire-форма — [mon-protocol.md](mon-protocol.md) (далее «протокол»); механика проб и её опытная проверка — [research: как mon-client гоняет пробу через xray-core и AWG в контейнерах](https://github.com/SBKubric/3ax-ui-proxy/blob/research/mon-client-probes/docs/research/mon-client-probes.md) (далее «research»).

## 1. Назначение и границы

mon-client — коробка в целевом регионе: **один контейнер, один Go-процесс без capabilities**. Для xray-targets он держит дочерний `xray` (бинарь из официального образа, конфиг в файл, stderr в pipe), для AWG-targets — встроенный `amneziawg-go/v3` с `tun/netstack` (gVisor, in-process, без `/dev/net/tun`, маршрутов и прав). Раз в минуту он гоняет tunnel probe к mon-server через каждый туннель и шлёт один heartbeat мимо туннелей. Успех пробы определяет mon-client; состояние targets считает mon-server.

Вне scope v1: пробы WireGuard и MTProto; `awg-quick`, netns и policy routing в контейнере (research §3.2, §4 — не работают без privileged или дают ложный UP); упаковка и инсталлер (туман карты).

## 2. Запуск, параметры, state-файл

- Единственный параметр — `serverUrl` (`https://<ip>:443`), через флаг `--server` или ENV `MON_SERVER_URL`. Опционально `--state-dir` (`/var/lib/mon-client`), `--xray-bin` (`/usr/local/bin/xray`), `--log-level`.
- **State-файл** `state.json` (0600): `{monClientId, token, serverUrl, appliedRevision, lastAckSeq}` (`lastAckSeq` — последний `ackSeq` из ответа heartbeat, §6). Пока его нет — регистрация (§3). Пропал или `401` — стереть и регистрироваться заново.
- Рабочие файлы в state-dir: `xray.json` (сгенерированный конфиг), `xray.log` не ведётся (stderr читается в pipe), `cycles.json` — буфер неподтверждённых циклов (§6).
- mon-client доверяет системным CA; пиннинга нет.

## 3. Регистрация

Протокол §2.

1. Сгенерировать pairing code `[A-Z2-9]{6}`, **напечатать в лог** (`registration request sent, pairing code 7K3F9Q`), `POST /v1/register {pairingCode, hostname, version, publicIp}` (`publicIp` — best effort, из первого исходящего соединения; пусто допустимо).
2. `202 {requestId, pollAfter, expiresAt}` → опрос `GET /v1/register/<requestId>` каждые `pollAfter` (10 с) до `approved` (сохранить `monClientId`, `token` в state-файл → §4), `rejected` (ждать 1 ч, новая заявка) или `410` (новая заявка с новым кодом; backoff 1 → 2 → 5 мин, дальше каждые 5 мин).
3. `429` → ждать `Retry-After`. Сетевые ошибки — тот же backoff.

## 4. Конфиг и его применение

Протокол §4.

1. `GET /v1/config` при старте, после регистрации и когда `configRevision` в ответе heartbeat отличается от `appliedRevision`.
2. **Сборка**: из `targets` документа
   - xray-targets (`link`) → один `xray.json` (research §2.1): на target socks-inbound `127.0.0.1:<port>` (`auth: noauth`, порты с 10801 по порядку, `tag in-<kind>-<inboundId>-<path>`), outbound из ссылки (`vless`/`vmess`/`trojan`/`shadowsocks`; для Reality — `security: reality`, `serverName/fingerprint/publicKey/shortId/spiderX[/mldsa65Verify]`, `flow`, `encryption: none`; `network tcp`≡`raw`), правило routing `inboundTag → outboundTag`, последним outbound `blackhole`; `log: {loglevel: info, access: none}`, `mux` выключен (свежий Reality-handshake на каждую пробу);
   - AWG-targets (`conf`) → разбор `.conf` в UAPI: ключи base64 → hex, `Jc/Jmin/Jmax/S1..S4/H1..H4/I1..I5` и прочие AWG-параметры в нижнем регистре; `Address` → `localAddresses` netstack, `MTU` (default 1420), `DNS` игнорируется; `Endpoint`, `AllowedIPs`, `PersistentKeepalive` не нужен. `Endpoint` может быть `host:port` с именем хоста: amneziawg-go принимает в UAPI только `endpoint=<ip>:<port>` и сам не резолвит ([research #60](https://github.com/SBKubric/3ax-ui-monitoring/issues/60)), поэтому имя резолвит проба (§5), а при разборе проверяется только наличие порта.
3. **Применение между циклами, поцелевое** (решение [#53](https://github.com/SBKubric/3ax-ui-monitoring/issues/53) п. 3): дождаться проб в полёте; каждый target разбирается отдельно — ссылка, которая не разбирается (в т. ч. неподдерживаемые схема/транспорт/security), `.conf`, который не разбирается (в т. ч. неизвестный ключ AWG), и AWG-target, на котором пробный `IpcSet` на netstack-устройстве **без `Up`** падает (имя хоста в `Endpoint` на время пробы подменяется адресом-заглушкой — его резолвит проба, §5), **отвергаются**: в `xray.json` и в набор проб не попадают, уходят в каждом heartbeat как `client.rejectedTargets` (`{target, error}`, первая строка ошибки ≤ 256 символов), лог `WARN target rejected`. Из остальных — записать `xray.json`, `xray -test -c xray.json`; успех → перезапустить дочерний xray (SIGTERM, ждать, старт, дождаться готовности socks-портов), `appliedRevision = configRevision`. Отвергнуты все targets — ревизия всё равно применяется (пустой набор проб), чтобы heartbeat нёс отказы под новой ревизией. Ошибка ревизии целиком (`-test` упал, xray не перезапустился, не записался `state.json`) → остаться на старой ревизии (и её `rejectedTargets`), продолжить пробы по старому конфигу, `configError` в каждом heartbeat (первая строка ошибки, ≤ 256 символов), повторять `GET /v1/config` при каждой смене ревизии. Грейса нет: результаты по удалённым targets отбрасываются.
4. Первый старт без валидного конфига (нет targets) — цикл идёт пустым: heartbeat без результатов.

## 5. Цикл проб

Протокол §5; параметры из `probe` конфига (default 60 с цикл, бюджет 20 с, connect 5 с, TLS 10 с, заголовки 10 с, джиттер старта 0–5 с, heartbeat 10 с).

- **Тикер** (решение #53 п. 5): первый цикл стартует после случайного джиттера `[0, startJitterMs)` — это единственный джиттер; каждый следующий — ровно через `intervalMs` после *запланированного* старта предыдущего (через `Clock`), сколько бы ни длился цикл: цикл 25 с при интервале 60 с даёт период 60 с. Цикл, переживший следующий тик, не вызывает догоняющего цикла: просроченные тики пропускаются, старт — на ближайшем тике впереди (цикл 70 с → период 120 с). Все targets **параллельно**, каждая проба под `context.WithTimeout(budgetMs)`.
- **Перезапуск xray перед циклом** (решение #53 п. 4): если в применённой ревизии есть xray-targets, а дочерний xray не работает (упал между циклами), — одна попытка `Restart` на применённом `xray.json` (с ожиданием socks-портов, ≤ 10 с); следующая попытка — в следующем цикле, т.е. backoff = интервал. Не поднялся → xray-пробы этого цикла не выполняются (не ложный `tcp_refused` на loopback; AWG-пробы и heartbeat идут), `configError = "xray: <первая строка stderr>"` в каждом heartbeat до восстановления. mon-server не выносит вердикт по отсутствующим результатам — такие targets уходят в `STALE`, не в `DOWN`. Поднялся → xray-пробы возвращаются, `configError` — снова ошибка ревизии (§4.3) или `null`.
- **Проба** — `GET <probeUrl>?target=<kind:inboundId:path>&n=<nonce>` с `Authorization: Bearer <token>`, `nonce` — 16 байт base64url на пробу. Клиент на пробу (`DisableKeepAlives: true`, свой `http.Transport`), `httptrace`:
  - xray: `Transport.Proxy = socks5://127.0.0.1:<port target'а>`; `tlsMs = TLSHandshakeStart→Done` (первая сквозная фаза: Reality-handshake + TCP real server→mon-server + TLS 1.3), `ttfbMs = WroteRequest→GotFirstResponseByte`, `connectMs` — к loopback (≈ 0), `handshakeMs = null`;
  - AWG: на пробу **пересоздать** netstack-device (`Close` → резолв endpoint → `NewDevice` + `IpcSet` + `Up`), `t0` перед `tnet.DialContext`. Резолв (решение #53 п. 1): перед каждой пробой каждый `endpoint=` с именем хоста заменяется на `endpoint=<ip>:<port>` резолвером хоста (из ответа берётся первый IPv4, иначе первый адрес); IP-endpoint не трогается и не резолвится. Смена IP за именем подхватывается в следующем цикле; `connectMs` вручную вокруг dial; `handshakeMs = last_handshake_time − t0` из `IpcGet()` (опрос ~50 мс до изменения, максимум `connectMs`); `tlsMs`, `ttfbMs` — хуки работают.
    - **UDP-bind с батчем 1** ([#90](https://github.com/SBKubric/3ax-ui-monitoring/issues/90), причина — [#85](https://github.com/SBKubric/3ax-ui-monitoring/issues/85)): device поднимается на своём `conn.Bind` с `BatchSize() == 1` — один dual-stack UDP-сокет, `ReadFromUDPAddrPort`/`WriteToUDPAddrPort`, без `SetMark` и sticky source, — а не на `conn.NewDefaultBind()`. На linux тот батчит по 128 датаграмм, и amneziawg-go выделяет под батч 128 × 64 КБ на каждую routine приёма (v4, v6) и на чтение TUN — ~25 МБ на device. Утечки нет, но после `Close` буферы переживают два GC в `sync.Pool` устройства, а device создаётся на каждую пробу раз в минуту: цель кучи GC и RSS mon-client раздувались в разы выше живой кучи, и на маленькой машине это давало swap и зависания циклов на секунды. Проба — один handshake и несколько пакетов HTTPS, батчи ей не нужны; с батчем 1 проба аллоцирует около 1 МБ (тест держит порог). Обёртка над `StdNetBind` с переопределённым `BatchSize()` не годится: её GRO-путь на linux рассчитан на полный батч буферов. `Check` (§4.3) строит device на том же bind.
- **Diagnostic sweep** (решение [#100](https://github.com/SBKubric/3ax-ui-monitoring/issues/100), протокол §5.3): `sweepTargets` конфига применяются вместе с ревизией (§4), но в набор проб цикла не входят. Ответ heartbeat с `sweep` — задание на следующий цикл: он пробирует ещё и `sweepTargets` названных `inboundKind` (параллельно, с теми же бюджетами) и одновременно делает host reachability check каждого `hosts[]` — серию из 10 ICMP-эхо через ~200 мс с ожиданием ответов ~1 с (`lossPct`, средний RTT) по **непривилегированному** ICMP-сокету (`SOCK_DGRAM`/`IPPROTO_ICMP`, `golang.org/x/net/icmp` `udp4`; capabilities не нужны, нужен `net.ipv4.ping_group_range`, включающий группу процесса — Docker с 20.10 ставит его контейнеру сам). Сокет не открылся — `reason: icmp_unavailable`, имя не резолвится в IPv4 — `resolve_failed`; это «не измерено», не 100% потерь. Результаты — в поле `sweep` цикла (не в `results`); задание одноразовое.
- **Успех** = `200`, JSON с тем же `nonce`, в бюджете. `egressIp` из ответа кладётся в результат.
- **Провал и `reason`** (словарь контракта §4.6): `tcp_refused` (dial refused), `tcp_timeout` (connect не уложился), `tls_timeout` (TLS-handshake не уложился), `reality_real_cert` (строка `REALITY: received real certificate` в stderr xray за окно пробы в сессии target'а, см. сопоставление ниже), `awg_no_handshake` (`last_handshake_time` не изменился за `connectMs`; также — туннеля не было вовсе: имя endpoint не разрезолвилось, `detail: "endpoint: resolve <host>: …"`, или устройство не поднялось, ошибка `IpcSet`/`Up` в `detail`; повтор — в следующем цикле, решение #53 пп. 1–2), `http_error` (не `200` или чужой `nonce`), `probe_timeout` (общий бюджет). `detail` ≤ 256 символов: последняя строка `failed to process outbound traffic` / `REALITY: …` из stderr xray или текст ошибки Go.
- Читатель stderr xray: кольцевой буфер последних 500 строк с временем. **Сопоставление с target** (решение #53 п. 6): несколько xray-targets могут указывать на один `addr:port` real server'а, поэтому сессия относится к target'у по outbound-tag — строка диспетчера `[<session-id>] app/dispatcher: taking detour [<outbound-tag>] for [tcp:<dest>:<port>]` (tag `out-<kind>-<inboundId>-<path>` уникален на target; формат проверен на Xray 26.3.27, loglevel `info`); в окне пробы берутся session-id с tag'ом target'а, и из их строк — `REALITY: …` / `failed to process outbound traffic`. Фолбэк, если в окне нет detour-строки с этим tag'ом: session-id из `dialing TCP to <addr>:<port>` (адрес и порт из ссылки target'а), кроме сессий, которые detour-строка уже отдала другому outbound.

## 6. Heartbeat и буфер

Протокол §5.3.

- После цикла — один `POST /v1/heartbeat` (свой Transport без прокси, таймаут `heartbeatTimeoutMs`): `{monClientId, configRevision: appliedRevision, client: {version, xrayVersion, uptimeMs, configError}, cycles: [...]}`. Цикл: `{seq (монотонный, в state), ts (начало цикла, ms), unverified, results[]}`.
- **Буфер** `cycles.json`: цикл добавляется до отправки; ответ `200 {ackSeq}` удаляет все `seq ≤ ackSeq`; не подтверждён (сеть, 5xx, таймаут) → цикл остаётся с `unverified: true` и досылается в следующем heartbeat вместе с новыми; ≤ 60 циклов, старые вытесняются. Пробы при этом **продолжаются**.
- **Seq** (протокол §5.3, решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 1): счётчик в `cycles.json`, начинается с 1 при каждой новой регистрации (после `401` `cycles.json` стирается вместе с `state.json`). После каждого подтверждённого heartbeat `ackSeq` сохраняется в `state.json` (`lastAckSeq`). `cycles.json` пропал или не разбирается (повреждённый откладывается в сторону) → следующий seq = `lastAckSeq + 1`, не 1: mon-server отбросил бы seq ≤ своего `last_ack_seq` как дубликаты. `ackSeq` выше счётчика → счётчик переходит на `ackSeq + 1`.
- Ответ: `configRevision` ≠ `appliedRevision` → §4 после текущего цикла; `sweep` → обход в следующем цикле (§5).
- `401 token_revoked` → остановить пробы, стереть state-файл, §3. `403 disabled` → остановить пробы, heartbeat раз в 5 мин до `200`. `410` на регистрации — §3.

## 7. Логи и диагностика

Человекочитаемый лог в stdout: регистрация с pairing code, применение ревизий, результат каждой пробы одной строкой (`probe xray:12:proxy ok tls=47ms ttfb=39ms` / `probe awg:0:proxy FAIL awg_no_handshake …`), результат heartbeat (`ack 1441`, `buffered 3 cycles`), ошибки конфига. Уровень `info` по умолчанию; `debug` добавляет stderr xray целиком.

## 8. Структура кода

```
cmd/mon-client/main.go        — флаги, запуск
internal/state/               — state.json, cycles.json
internal/register/            — §3
internal/config/              — GET /v1/config, разбор ссылок и .conf, генератор xray.json, UAPI
internal/xray/                — дочерний процесс, -test, рестарт, читатель stderr
internal/awg/                 — netstack-device на target
internal/probe/               — цикл, httptrace, reason
internal/heartbeat/           — отправка, буфер, ackSeq
internal/hostcheck/           — host reachability check (ICMP) для diagnostic sweep
docs/spec/mon-client.md
```

Зависимости: `github.com/amnezia-vpn/amneziawg-go/v3` (device, conn, tun) и `gvisor.dev/gvisor` (стек netstack; обёртка TUN своя — копия `tun/netstack` с безопасным `Close`, #69), `golang.org/x/net/proxy` (socks5 dialer не нужен: `Transport.Proxy` умеет `socks5://`), стандартная библиотека.

## 9. Открытое из research (UNVERIFIED, не блокирует)

- Живой прогон `tun/netstack` против AWG-сервера стенда.
- Отменяет ли xray фоновые ретраи dial при закрытии socks-соединения (влияет только на нагрузку).
- Вариант «xray как библиотека» (`core.New`/`core.Dial`) для точного замера Reality-handshake — возможная замена socks в v2.

## 10. План реализации

Каждый шаг — отдельный коммит; тесты `go test ./...`; mon-server — httptest-стаб протокола.

1. Флаги, state-файл, лог; тест round-trip state.
2. Регистрация §3 на стабе: код в логе, опрос, `approved` → state, `rejected`/`410`/`429`/backoff.
3. Разбор ссылок → outbound (таблица research §2.1: vless+reality обязательные поля, `tcp`≡`raw`, ошибки), разбор `.conf` → UAPI (base64→hex, нижний регистр, `Address`/`MTU`); golden-тесты; `xray -test` на сгенерированном конфиге в CI через образ `ghcr.io/xtls/xray-core`.
4. Дочерний xray: старт, `-test`, рестарт между циклами, читатель stderr с кольцевым буфером; тест сопоставления `dialing TCP` / `REALITY: received real certificate` с target.
5. Проба xray через socks5 + httptrace; тесты на стабе mon-server: `ok`, `http_error` (чужой nonce), `tls_timeout`, `tcp_refused`.
6. Проба AWG через netstack: пересоздание device, `handshakeMs`, `awg_no_handshake`; интеграционный тест с `amneziawg-go` сервером в контейнере (первый живой прогон netstack — закрывает UNVERIFIED research §8).
7. Цикл §5: параллельность, бюджеты, джиттер; heartbeat и буфер §6 с `ackSeq`, unverified, вытеснением; тесты.
8. Применение ревизии §4: между циклами, `configError`, отбрасывание результатов удалённых targets.
9. `401`/`403`/`410` ветки; `version`.
10. Dockerfile-набросок для ручной проверки на стенде (упаковка и инсталлер — отдельно, туман карты): один контейнер без capabilities, проверить регистрацию, `UP` по обоим path, `DOWN` при остановке inbound'а, `reality_real_cert` при подмене SNI-сайта.
