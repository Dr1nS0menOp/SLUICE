# Splunk notes

Facts about Splunk's configuration and SPL that `sluice-rules` (`splunk/`) relies on. Read
from Splunk's search reference and checked against the ES Content Update app
(`DA-ESS-ContentUpdate` v6.8.0, 2026-10-17). Not yet checked against a running Splunk: its
image needs the Splunk General Terms accepted (ADR 0026).

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
  by default.

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
- `field=value` matches field values case-insensitively; `*` is a wildcard. Field names are
  case-sensitive.
- Comments are ```` ```text``` ````; ESCU has them inside searches. Without stripping them,
  their backticks read as macro calls.
- ESCU's macros for data sources (`` `sysmon` ``, `` `wineventlog_security` ``) test only
  `source`, `sourcetype` or `eventtype`; per-search `` `…_filter` `` macros are `search *`.
- `drop_dm_object_name(1)` and other CIM macros live in `Splunk_SA_CIM`, not in ESCU; ESCU
  uses them after `tstats` only.
- JSON events: Splunk names an array's members `a{}.b`, a path no record has.
