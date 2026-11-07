# ADR 0039: `sluice verify`, whether a plan still holds later

- Status: Accepted
- Date: 2026-11-08

## Context

Contract rule 5 says every cut is proven before it is enforced, "and is re-verified
continuously after enforcement". Sluice advises only (ADR 0030): it never sits in the data
path, so it cannot watch what runs. Until now, re-verifying meant running `sluice analyze`
again, which writes a new plan instead of checking the one that runs. And two things change
under a deployed plan:

- **The rules.** A rule added in the SIEM after the analysis is not protected: the plan may
  remove a field it reads, or count events it would match (architecture, "Nothing watches what
  runs"). A rule Sluice now reads differently is the same case.
- **The data.** A format that changes fits no template and is sent whole (rule 1), which costs
  savings, not detections. Values learned from one day may hold less on the next, which also
  costs savings only, since a value guard sends any other value (ADR 0032).

`sluice prove` proves a configuration on a sample, for CI. It knows neither the plan's rules
nor what the plan saved.

## Decision

1. **`plan.json` records every rule it was proven with**, as a fingerprint: the rule's id and
   the SHA-256 of its requirements as compact JSON. These are the log source, the fields it
   reads, its pre-filter and its flags. Rules sharing an id are digested together. A fingerprint
   of what Sluice *read*, not of the text, means a rule whose text changed but reads the same is
   still protected. A rule a newer Sluice reads differently is not, and is reported.
2. **`sluice verify --analysis OUT --input NEW --sources … <the rules of now>`** takes the plan as
   it was written, a newer sample and the rules the SIEM runs now (fetched again). It then:
   - proves the plan's `vector.yaml`, or `--config`, on the new sample with the rules of now, as
     `sluice prove` does. Sigma always runs; Sentinel's rules run with `--kusto`, Elastic's with
     `--elasticsearch`;
   - compares the rules with the plan's fingerprints: added, read differently, gone;
   - checks that a plan that counts events still has rules known to be complete (ADR 0021);
   - reports the savings on the new sample against the plan's, the share of bytes of no kind of
     event the plan knows, and the kinds whose saving fell by 10 points or more.
3. **The verdict and its exit code.**
   - *Holds* (0): the same alerts on the new sample, and no rule the plan was not proven with.
   - *Out of date* (3): the same alerts, but rules were added or changed, the plan does not
     record its rules, or a counting plan's rules are not known to be complete. Run
     `sluice analyze` again before relying on it.
   - *Does not hold* (1): the alerts differ; a detection would change. Do not deploy the plan,
     and take it out if it runs.

   Less saving is never a reason against a plan. It is reported, and an analysis may save more.
4. **A sample without alerts fails** unless `--allow-no-alerts` is given, as with `prove`. The
   rule comparison is still printed.
5. **Splunk's searches are compared, not run.** `verify` reads them, so a changed search makes
   the plan out of date, but it does not start a Splunk for them.
6. **Run it on a schedule.** A daily job that fetches the rules, takes the day's sample and runs
   `sluice verify --json` is the re-verification rule 5 asks for. Sluice still changes nothing:
   the job's owner acts on the verdict.

## Consequences

- A rule added in the SIEM is caught by the next `verify`, not only by the next analysis.
- `plan.json` grows by a line per rule; its format stays `sluice.plan/1` (ADR 0038). A plan
  written before 1.0 has no fingerprints, so `verify` calls it out of date.
- `verify` proves the plan as `vector.yaml` carries it out. A native configuration was proven,
  in its own engine, to remove nothing Vector keeps on the analysis's sample only. It is not run
  again here; a new analysis with `--native` proves it on newer data.
- A new Sluice that reads a rule more precisely makes `verify` report it as changed, once. That
  is correct: the plan was proven with the old reading.
