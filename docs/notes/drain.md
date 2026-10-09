# Drain: behaviour and limits

These notes cover Sluice's implementation in `crates/sluice-discover/src/drain.rs`. It uses
Drain3's defaults (similarity 0.4, max 100 children), except for **depth 3** instead of 4: we
route on the program name only. At depth 4 the second routing token was the sudo user, which
split `sudo` into one template per user × command (9) instead of one per command (3). They were verified on the synthetic
sample on 2026-10-09.

## How lines are compared

0. **Header split** (`preprocess.rs`). A syslog header, either BSD style (`Oct 10 08:00:02 host
   prog[pid]:`) or ISO style (`2026-…T…Z host prog[pid]:`), is replaced by the program name.
   Without this step, three timestamp tokens make unrelated lines look alike, and the tree routes
   on the month. On the synthetic sample, leaving the header in merged `CRON … session closed`
   with `systemd-logind: New session N of user X`. With the split, they stay apart.
1. **Masking.** Each whitespace token is masked first: digit runs become `<NUM>`, and hex
   identifiers (`0x…`, or 8+ hex chars with a digit) become `<HEX>`.
2. **Routing.** Lines go through the tree by token count, then by their first `depth - 2` tokens.
   Tokens that contain digits route through `<*>`.
3. **Similarity.** At a leaf, similarity is the number of equal constant tokens divided by the
   line length. Wildcards count as unequal.
4. **Joining.** A line joins the best cluster at or above the threshold. Positions where the
   cluster and the line differ become `<*>`.

## Known limit: masked tokens inflate similarity

Masked placeholders compare as equal, so lines that share mostly variable parts look alike.

**Observed:** an nginx `/healthz` probe and a `curl` request both have 12 tokens. After masking,
the IP, date, status and byte count are equal, so the two lines score about 0.8 similar and merge.
The path then becomes `<*>`, and health checks get no template of their own.

Changing the threshold doesn't fix this. Masking makes these lines too similar, and a higher
threshold splits real templates elsewhere.

**Consequence and plan:**

- Text discovery is coarse. That is acceptable for safety, because a coarse template only
  reduces less.
- For known text formats (nginx, sshd, sudo), community recipes parse the line into fields.
  Parsed fields are discriminated like JSON, so `/healthz` can become its own template and get
  an L3 recipe.
- Unknown text formats rely on Drain alone.
