# Security Policy

RailMon captures decrypted TLS traffic from AI-agent processes. It sees request
and response bodies in the clear, and it runs with the privileges eBPF needs. A
weakness here can expose the contents of somebody's agent conversations. We
treat reports accordingly.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use the repository's **Security** tab to open a private vulnerability report.

Please include what an attacker can do (not only what is wrong), the version or
image digest, the smallest reproduction you have, and whether you have told
anyone else.

## What to expect

| | |
| --- | --- |
| Acknowledgement | within 3 working days |
| First assessment | within 10 working days |
| Progress | at least every 10 working days until it closes |

We ask for **90 days** before public disclosure and will usually be much
faster. If a fix will take longer we will say so and agree a date rather than
let it lapse quietly. You will be credited unless you would rather not be.

## Scope

In scope: this repository, its published image, and its release workflow.

Out of scope, but tell us anyway if it looks serious: AgentSight and other
upstream dependencies (report upstream; we will help), and anything requiring
an attacker who already has root — RailMon needs `CAP_BPF` or root to attach at
all, and that is assumed.

## What this component does and does not protect

This is the part worth reading before reporting, because it defines what a
vulnerability here means.

- **Credential headers are stripped before anything leaves the process.**
  `Authorization`, `x-api-key`, `Cookie` and others are redacted by AgentSight's
  analyzer chain, and RailMon additionally scrubs `api-key`, `x-goog-api-key`
  and `proxy-authorization`, which that chain does not cover. The raw wire text
  is discarded rather than carried through, for every message the parser
  recognises. An SSL event it does *not* recognise — a `CONNECT` to a forward
  proxy, which is exactly where `Proxy-Authorization` appears — passes through
  with its wire text intact, so credential header *lines* in that text are
  scrubbed separately. Two classes of event, both covered.
  **If a credential header reaches the output, that is a vulnerability — report
  it.**
- **Bodies are not redacted at all.** Whatever of a body is captured is written
  through unchanged, including anything secret inside it — an OAuth
  `client_secret` in a form post, a token in a JSON payload. *The output file is
  as sensitive as the traffic it captured.* It is not a sanitised artifact and
  must not be treated as one.

  Bodies are, separately, often **incomplete**: an HTTP/1.1 streamed response is
  recorded from its first SSL read only (measured at 81 of 532 bytes on one
  Anthropic-shaped stream), and upstream caps a body at 1 MiB. Do not read
  capture as a completeness guarantee in either direction — it is neither
  redacted nor whole.
- **`--mode raw` is not a redacted mode.** It forwards analyzer events directly.
  Credential header lines in raw wire text are scrubbed, but this mode exists
  for debugging and should not be pointed at a shared sink.
