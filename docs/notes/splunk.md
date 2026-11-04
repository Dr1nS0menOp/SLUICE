# Splunk notes

Facts about Splunk's configuration, SPL and REST API that `sluice-rules` (`splunk/`) and
`sluice-splunk` rely on. The configuration and SPL facts were read from Splunk's search reference
and checked against the ES Content Update app (`DA-ESS-ContentUpdate` v6.8.0, 2026-10-17). The
REST, collector and search facts were verified against Splunk Enterprise 10.6.1.1 (the
`splunk/splunk:10.6.1.1` image, trial licence) on 2026-11-03 (ADR 0037).

## Configuration

- `savedsearches.conf`: one stanza per search. `search` holds the SPL; a line ending in `\`
  continues on the next. `enableSched = 1` schedules it; Enterprise Security marks correlation
  searches with `action.correlationsearch.enabled = 1`. ESCU ships all 2,223 of its searches
  with `disabled = 1`: the customer enables what they use.
- `macros.conf`: `[name]`, or `[name(n)]` for a macro with `n` arguments, named in `args =`
  and written `$arg$` in `definition`. `iseval = 1` makes the definition an expression.
- The REST API (`/servicesNS/-/-/saved/searches`, `/servicesNS/-/-/admin/macros`, with
  `output_mode=json`) answers `{"entry": [{"name", "content": {…}}]}`, `content` holding the
  same settings; booleans are JSON booleans (`is_scheduled`, `disabled`). Paging:
  `count` and `offset` in the request, `paging.total` in the answer (`count=0` means all).
  `-/-` in `servicesNS` means every user and app, so names repeat across apps; `acl.app`
  says whose an entry is. Authentication: `Authorization: Bearer <token>` for an
  authentication token, or basic. The management port (8089) has a self-signed certificate
  by default. A scheduled search is created with `POST /servicesNS/nobody/<app>/saved/searches`
  (`name`, `search`, `is_scheduled=1`, `cron_schedule`), a macro with
  `POST /servicesNS/nobody/<app>/admin/macros` (`name`, `definition`).

- `props.conf` derives fields at search time, per `[sourcetype]`, `[source::…]` or
  `[host::…]`: `FIELDALIAS-x = orig AS new` (or `ASNEW`), `EVAL-new = expr`, `LOOKUP-x =
  table in [AS field] OUTPUT|OUTPUTNEW out [AS field]` (without `OUTPUT`, every column),
  `EXTRACT-x = regex [in field]` with named groups, `REPORT-x = t1, t2` naming
  `transforms.conf` stanzas (`REGEX` with `FORMAT = name::$1`, or `DELIMS` with `FIELDS`;
  `SOURCE_KEY` defaults to `_raw`). `FORMAT = $1::$2` and groups named `_KEY_n`/`_VAL_n` take
  the field name from the data. Search-time order: extractions, `KV_MODE`, aliases, `EVAL`,
  lookups. REST: `configs/conf-props` and `configs/conf-transforms`.

## SPL

- Boolean operators are capitals only (`OR`, `AND`, `NOT`; lower case is a search term).
  Precedence: parentheses, `NOT`, `OR`, then `AND` (implied between terms). `a b OR c` is
  `a AND (b OR c)`, unlike most languages.
- `field=value` matches field values case-insensitively (`User=ALICE` matches `alice`); `*` is
  a wildcard. Field names are case-sensitive. A number compares as a number: `Num=3` matches a
  JSON `3.0`.
- `field!=value` matches only events that have the field; `NOT field=value` also those without
  it. A test on an event type or a tag Splunk has no definition of matches nothing, and so
  does its `NOT` (`NOT eventtype=foo` kept none of 3 events): the proof replaces such tests
  instead of trusting them.
- An inline time modifier (`earliest=-24h`) overrides the time range the search is dispatched
  with.
- Comments are ```` ```text``` ````; ESCU has them inside searches. Without stripping them,
  their backticks read as macro calls.
- ESCU's macros for data sources (`` `sysmon` ``, `` `wineventlog_security` ``) test only
  `source`, `sourcetype` or `eventtype`; per-search `` `…_filter` `` macros are `search *`.
- `drop_dm_object_name(1)` and other CIM macros live in `Splunk_SA_CIM`, not in ESCU; ESCU
  uses them after `tstats` only.
- JSON events: Splunk names an array's members `a{}.b` and a nested key `a.b.c`.

## Running searches (`search/jobs`)

- `POST /services/search/jobs` with `exec_mode=oneshot` answers the results at once:
  `{"messages": [...], "results": [{…}]}`, every value a string (or an array for a multivalue
  field). `count=0` asks for every row, but Splunk caps the rows at `maxresultrows` (50,000 in
  `[restapi]` and `[searchresults]` of `limits.conf`) and says so only in a `WARN`, and only
  when more were asked for: 50,000 rows come back for 50,001 or 60,000.
- A search Splunk refuses comes back two ways: `400` with a `FATAL` message (an unknown
  command, a macro it has no definition of), or `200` with a `FATAL` message and no `results`
  (a lookup or data model it does not have, mismatched parentheses, an unknown eval function).
  An index that does not exist is no error: the search finds nothing.
- `search/v2/jobs/export` streams every row without a cap, one JSON object a line, the last
  with `"lastrow": true`. But a search that fails at run time answers `200` with an empty
  body: no message, no `lastrow`. The proof uses `oneshot`.
- `earliest_time=0` and `latest_time=2147483647` cover all time; a later `latest_time`
  (`4102444800`) is refused: "latest_time must be after earliest_time".
- A search returns only the fields it names: the JSON fields a search does not use are not in
  its rows, and neither is an indexed field, even with `rf=<field>` or
  `adhoc_search_level=verbose`. Naming it in the search does it: the proof ends every search
  with `| eval sluice_event=sluice_event`, which adds the event's id to the rows that are events
  and nothing to a count or a table. `table *` and `stats values(*)` show it too.
- Splunk runs `6 + 1 × CPUs` searches at a time (`base_max_searches`, `max_searches_per_cpu`);
  the `admin` role's quota is 50.

## Sending events (the HTTP Event Collector)

- The container image turns the collector on (port 8088, TLS); its settings are
  `GET /services/data/inputs/http/http` (`disabled`, `port`, `enableSSL`). A token is
  `POST /services/data/inputs/http` (`name`), its value in `content.token`; without `indexes`
  it may send to any index. The collector is not on the management port (`401` there).
- `POST /services/collector/event` with `Authorization: Splunk <token>` takes JSON objects one
  after another: `time` (seconds, a fraction kept to the millisecond), `index`, `sourcetype`,
  `source`, `host`, `fields` (indexed fields) and `event`. An object `event` becomes `_raw` as
  sent. One request of 5,003 events (1 MB) took 0.02 s, and every event was searchable after
  0.5 s.
- **It accepts events for an index that does not exist and drops them**, answering
  `{"text":"Success","code":0}`; splunkd logs "Received event for unconfigured/disabled/deleted
  index=… Dropping them". Only a count afterwards shows what arrived.
- Indexed fields from `fields` are searchable as `name=value` and `name::value`, and
  `| tstats count where index=x name=value` counts by them.
- Search-time JSON extraction (`KV_MODE = auto` for a sourcetype without settings) reads only
  the first 10,240 characters of an event (`[kv] maxchars`): a field after them is not
  extracted, though a bare term still finds its value in `_raw`. The collector's `/event`
  endpoint does not truncate `_raw` (a 20,072-character event stayed whole).

## Indexes (`data/indexes`)

- `POST /services/data/indexes` (`name`, and settings such as `frozenTimePeriodInSecs`)
  answers `201`, `409` if the name exists. The answer's `isReady` may still be `false`, with
  `disabled: true`: `GET /services/data/indexes/<name>` says when it is ready.
- **Splunk adds and removes indexes in the background, one at a time.** An index added while
  another was removed stayed not ready until Splunk loaded its indexes again ("Unable to reload
  indexer after adding: reason='already reloading or shutting down, will not reload'. Restart
  required."), and could not be removed meanwhile ("Unable to remove index … until after a
  restart"). `POST /services/data/indexes/_reload` asks for a reload.
- `DELETE /services/data/indexes/<name>` answers `200` and removes the data later. **A new
  index of the same name, made right after, holds the old one's events** (3 of 3 came back):
  never reuse a name.
- Events years old stay searchable when `frozenTimePeriodInSecs` is set high (2020's were);
  events to 2030 too.

## Licence

- The image starts only with `SPLUNK_START_ARGS=--accept-license` and
  `SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com`; `SPLUNK_PASSWORD` sets `admin`'s
  password. Without a licence file it runs Splunk Enterprise's trial (`activeLicenseGroup:
  Trial`), 500 MB a day.
