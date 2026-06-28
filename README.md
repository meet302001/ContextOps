# ContextOps

A small CLI that captures a repository's file context into shareable bundles for
downstream / AI-readable context libraries.

It produces two artifacts per run:

- `context.md` — human-readable
- `context.json` — machine-readable

## Usage

```bash
python contextops/contextops.py --repo context-bundle
```

Options:

| Flag | Default | Description |
| --- | --- | --- |
| `--repo` | `context-bundle` | Repository to scan. |
| `--project` | scanned dir name | Project name used in the output folder. |
| `--out` | `s3-bucket` | Simulated S3 bucket root directory. |

## Output layout (simulated S3)

The bundle is **never** written inside the scanned repo. It is written to a
local folder that stands in for an S3 bucket:

```
s3-bucket/
  context_<project>/                  # one folder per project
    <pushed-by-user>_<UTC-datetime>/  # one tagged folder per capture
      context.md
      context.json
```

- The folder tag is `name-of-user_datetime`, where the user is the author of the
  latest git commit (the person who pushed the changes).

## Examples

A sample of real generated output is committed under
[`examples/`](../examples/) so you can see what a bundle looks like without
running the tool:

```
examples/
  context_context-bundle/
    meet302001_2026-06-28_010429Z/
      context.md
      context.json
```

Note: live `s3-bucket/` runs are git-ignored; the `examples/` copy is the only
bundle checked into the repo.

## Security policy

ContextOps is built to be safe to ship to a shared location:

- **Secrets are flagged, never copied.** Detected secret values (API tokens,
  AWS keys, DB passwords, Sentry DSNs, every `.env` entry, etc.) are reported
  with their file and line, but the value itself is replaced with
  `***REDACTED***`. The JSON findings only contain a short, non-reversible
  masked hint — not the secret.
- **Confidential files are excluded.** Files containing markers such as
  `confidential`, `do not distribute`, `not for ingestion`, or `trade secret`
  (e.g. `docs/proprietary-algorithm.md`) are listed as excluded with the reason
  recorded, and their content is withheld.
- **Binary assets are excluded.** Detected by extension and a NUL-byte sniff;
  their content is not captured (only a sha256 is recorded).

> Note: secret detection is heuristic. It is a strong safeguard, but review the
> generated bundle before sharing it widely, and never treat redaction as a
> substitute for rotating a secret that was actually committed.
