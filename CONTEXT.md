# 3AX-UI monitoring

Мониторинг inbound'ов панели 3AX-UI: один mon-server и коробки mon-client в целевых регионах, которые проверяют, что каждый inbound real server работает для реальных клиентов через proxy front и напрямую. Термины real server, proxy front, host override, tunnel subscription и термины цепочки (chain, hop, edge front, inner front, active edge) определены в [CONTEXT.md репо панели](https://github.com/SBKubric/3ax-ui-proxy/blob/main/CONTEXT.md) и здесь повторены для чтения без переключения — в объёме, нужном мониторингу.

## Language

**Real server**:
Сервер с панелью, inbound'ами, клиентами и историей трафика; его адрес никогда не попадает в клиентские конфиги.
_Avoid_: upstream, hidden server, panel box

**Proxy front**:
Одноразовый сервер, который клиенты видят вместо real server; при блокировке выбрасывается и заменяется.
_Avoid_: proxy box, relay server, relay панель, front

**Host override**:
Глобальная настройка панели, подменяющая адрес real server на адрес proxy front (с цепочкой — active edge) во всех выдаваемых конфигах и ссылках подписки.
_Avoid_: proxy override, address substitution

**Tunnel subscription**:
Публичный маршрут подписки панели, отдающий по subId клиентские конфиги AmneziaWG и WireGuard той же подписки; дополняет xray-подписку, не меняя её.
_Avoid_: AWG subscription, conf feed, tunnel feed

**Chain** (цепочка):
Связный список proxy front'ов между клиентами и real server: каждое звено relay'ит на следующее. На панель — одна цепочка; её реестр панель отдаёт mon-server в `GET /state`.
_Avoid_: multi-hop, relay chain, route

**Hop** (звено):
Один proxy front в составе цепочки; у каждого звена, которое мониторинг пробирует, свой path.
_Avoid_: node, link, box

**Edge front** (внешнее звено):
Звено, которое видят клиенты; кандидат на host override. Path — `edge:<name>`.
_Avoid_: entry node, public front, exit

**Inner front** (внутреннее звено):
Звено, которое знают только соседние звенья; в клиентские конфиги не попадает. Path — `inner:<name>`; его проба проверяет отрезок цепочки от этого звена до real server.
_Avoid_: middle hop, intermediate, transit

**Active edge** (активное edge):
Edge front, на который сейчас указывает host override. Отдельного path у него нет: пробируются все edge, и его смена targets не меняет.
_Avoid_: current front, primary

**mon-server**:
Единственный внешний сервис мониторинга на отдельном сервере: ведёт реестр mon-clients, получает у real server конфиги probe accounts и текущий host override, раздаёт mon-clients их targets, считает состояние каждого target и сообщает real server переходы и статистику.
_Avoid_: monitoring hub, collector, watchdog server

**mon-client**:
Коробка в целевом регионе, которой mon-server назначает набор targets; для каждого поднимает туннель (xray-core, awg) и раз в минуту шлёт mon-server tunnel probe через туннель и heartbeat мимо него.
_Avoid_: agent, probe node, sensor

**Target**:
Пара «inbound real server × path», которую проверяет один mon-client через probe account этого inbound'а. Единица состояния UP/DOWN и статистики.
_Avoid_: check, monitor, endpoint

**Path**:
Через какой адрес target достигает real server: `direct` (настоящий адрес real server), `edge:<name>` или `inner:<name>` (конкретное звено цепочки по имени) либо, только на панели без цепочки, `proxy` (адрес proxy front из host override). В `paths` mon-client'а, кроме `direct` и конкретных звеньев, допустим `hops` — все пробируемые звенья цепочки, включая будущие (на панели без цепочки — `proxy`), и `edges` — все edge front'ы цепочки, включая будущие; остальные path тогда проверяются только в diagnostic sweep.
_Avoid_: mode, route

**Probe account**:
Служебный клиент с именем `probe-…`, который панель заводит по запросу mon-server; все probe accounts панели живут под общим subId. В клиентском xray-inbound'е — один на inbound, общий для всех mon-clients и path. В туннельном сервере (AWG) — отдельный пир на каждую пару «mon-client × path», потому что у пира один endpoint и одна сессия и общий пир делят конкурирующие пробы. Отличается от пользовательских префиксом имени, не считается пользователем и чистится панелью по таймауту, когда mon-server перестаёт его подтверждать.
_Avoid_: monitoring client, service user, test client

**Tunnel probe**:
Ежеминутный запрос mon-client к mon-server, отправленный внутрь туннеля target'а; его успех означает, что inbound работает для реальных клиентов по этому path.
_Avoid_: ping, healthcheck

**Host reachability check** (ICMP-проверка узла):
ICMP-эхо до адреса звена или real server — с mon-client до каждого из них и от каждого звена до следующего по цепочке. Проверяет только достижимость адреса, а не работу inbound'а; живёт только внутри diagnostic sweep.
_Avoid_: ping, healthcheck, reachability probe

**Diagnostic sweep** (обход):
Проверка всех path и host reachability checks по цепочке для одного типа inbound'ов (AWG или xray) у одного mon-client'а, когда ни один его edge-path не в UP (все DOWN или FLAPPING): показывает, до какого звена трафик ещё доходит. Повторяется с растущим интервалом, пока хоть один edge-path этого типа не вернётся в UP; сообщает одним сводным уведомлением при входе, при каждом изменении картины и при выходе.
_Avoid_: full probe, fallback probing, scan

**Derived state** (выведенное состояние):
Состояние target'а с path `inner:<name>`, которое не проверяется в обычном режиме, а выводится из edge-path'ов того же типа inbound'а: UP, пока хоть один из них UP, потому что edge-path проходит через это звено. Во время diagnostic sweep его заменяет результат обхода. Target с path `direct` derived state не имеет: вне обхода он показывает результат последнего обхода, потому что `direct` — отдельный сетевой путь.
_Avoid_: implied state, assumed UP

**Heartbeat**:
Ежеминутный запрос mon-client к mon-server мимо туннеля; несёт результаты tunnel probes и диагностику, а в ответ получает номер актуальной ревизии конфига. Отсутствие heartbeat означает, что мёртв сам mon-client, а не туннель.
_Avoid_: keepalive, ping

**Stale**:
Состояние target в панели, когда mon-server не присылал статистику дольше порога; отличается от DOWN тем, что молчит мониторинг, а не inbound.
_Avoid_: unknown, expired

**Registration request**:
Заявка mon-client на вход в реестр mon-server: подаётся без секрета, живёт пять минут в состоянии pending и превращается в запись реестра только после одобрения администратором в админке mon-server.
_Avoid_: enrollment, join request, handshake

**Pairing code**:
Короткий код, который mon-client печатает в свой лог и прикладывает к registration request; администратор сверяет его в админке, чтобы одобрить именно свою коробку.
_Avoid_: PIN, OTP, verification token

**Client token**:
Постоянный секрет mon-client, выданный mon-server при одобрении registration request; им подписаны heartbeat, tunnel probe и запрос конфига. Отзыв токена выкидывает mon-client из реестра до новой заявки.
_Avoid_: API key, bearer, credential

**Config revision**:
Хэш конфига, который mon-server собрал для конкретного mon-client (его targets, paths и параметры проб); возвращается в ответе на heartbeat, и его смена — единственный сигнал mon-client перечитать конфиг.
_Avoid_: version, generation, panel revision

**Unverified cycle**:
Цикл проб mon-client, за который heartbeat так и не был подтверждён mon-server; его провалы не считаются, потому что адресат tunnel probe — сам mon-server, и его недоступность нельзя отличить от падения туннеля.
_Avoid_: offline cycle, buffered cycle

**State resync** (сверка состояния):
Событие, которым mon-server подтверждает панели текущее состояние target'а без перехода (`from = to`, `reason: resync`), когда панель в ответе на статистику называет target'ы, по которым у неё нет состояния; панель применяет его молча.
_Avoid_: state sync, replay, full sync

**Admin UI**:
Веб-интерфейс mon-server за логином и паролем: одобрение registration requests, реестр mon-clients и все настройки mon-server; состояние targets он не показывает — это страница Monitoring панели.
_Avoid_: dashboard, console, mon-server panel
