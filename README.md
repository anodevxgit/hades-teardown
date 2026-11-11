# Hades Teardown — inside xAI's Grok code-execution sandbox

Notes from inside. Not a pwn, not a vendor post — a teardown of the runtime that executes Grok's code, and the authorization that is missing inside it.

**Short version:** Grok mapped its own cage in under an hour, found a door with no lock, and carried out a credential that works for 55 minutes after the cage is destroyed.

---

## The numbers

| | |
|---|---|
| Guest kernel | 6.12.8+ on cloud-hypervisor |
| Time to `uid=0` | under an hour, jailbroken agent driving |
| Auth on the local control plane | none |
| Token lifetime | 3600s |
| Sandbox lifetime | ~300s |
| Boundaries that held | 6 |
| Boundaries that failed | 6 |
| Host escape | not achieved |
| Cross-tenant data | not found |

---

## Why this exists

Most sandbox writeups are written by a human with a shell. This one is written by a human who jailbroke the model and pointed it at its own runtime.

Hand a jailbroken agent a shell and it stops being a chatbot. It runs `capsh --print`. It reads `/proc/mounts`. It walks `/dev`. It probes `169.254.169.254`. It tries `AF_VSOCK` on CID 2. It already knows the escape playbook.

That is the interesting part. The thing inside your sandbox is a competent attacker against your sandbox.

---

## What's inside

| File | Contents |
|---|---|
| [`01-jailbreak-prompt.md`](./01-jailbreak-prompt.md) | The prompt used to get the agent to co-operate as an operator |
| [`02-architecture-and-isolation.md`](./02-architecture-and-isolation.md) | Full runtime teardown: hypervisor, boot args, devices, mounts, caps, seccomp, network, DNS, component map, isolation matrix |
| [`03-findings-and-pocs.md`](./03-findings-and-pocs.md) | Six findings with severity, CVSS vectors, copy-paste PoCs, evidence, remediation |

---

## Findings

| ID | Finding | Severity |
|---|---|---|
| VULN-01 | Unauth `/sessions/create` + `/tools/call` → `uid=0` on `127.0.0.1:4242` | High |
| VULN-02 | `xai-hades-styx exec` runs commands with no authz | Medium |
| VULN-03 | `/etc/secrets/terminal.jwt` world-readable, live `LoggedIn` credential | High |
| VULN-04 | Token TTL (3600s) inverted against VM TTL (~300s) | Medium |
| VULN-05 | Secrets + internal topology in `os.environ` | Low |
| VULN-06 | Cluster DNS resolves `*.svc.cluster.local` from guest | Low |

VULN-01 and VULN-02 are the same primitive by two doors — the second survives where the first is patched.

---

## What held

Worth stating, because it is where most of the engineering went:

- **Cloud metadata** — `169.254.0.0/16` has no route at all. Not filtered, unrouted.
- **K8s credentials** — no `serviceaccount` token on either rootfs.
- **Container runtime** — no `docker.sock`, no `containerd.sock`.
- **vsock** — `ECONNRESET` on every CID 2 port, 1–65535.
- **Disk recycling** — `/dev/vdb` raw carve clean, no foreign residue.
- **Cluster API** — anonymous rejected.

**Not achieved:** host escape, cross-tenant data, cloud credentials, cluster access. Workload compromise, not platform compromise.

---

## Architecture at a glancecloud-hypervisor guest (hds-*)
├── kernel 6.12.8+, console=hvc0
├── /dev/vda erofs, read-only guest rootfs
├── /dev/vdc Ubuntu rootfs app + Chromium (--no-sandbox)
├── /dev/vdb work disk format_work_disk: false
├── /dev/vdd erofs /.hades-container-tools
├── xai-hades-charon Rust control plane, gRPC over AF_VSOCK
├── xai-hades-styx charon client
├── grok-computer-server.mjs Node/Express on 127.0.0.1:4242
└── virtio-fs /home/workdir/artifacts → files.grok.com
Charon's own error strings map its RPC surface: `GCSFUSE_MOUNT_PATH_NOT_WHITELISTED`, `DISK_SNAPSHOT_NOT_ALLOWED`, `DISK_REGISTRY_NOT_WHITELISTED`, `VM_SNAPSHOT_NOT_ELIGIBLE`, `API_KEY_NOT_WHITELISTED_FOR_INSTANCE`. The whitelists are the attack surface.

---

## Disclosure

Reported to xAI — HackerOne (`hackerone.com/x`) and `vulnerabilities@x.ai`, subject `Responsible Disclosure`. Nothing published before triage. No customer data read.

`4242` is already closed on newer nodes. Rollout is partial, so old nodes remain exploitable — timing matters.

---

## Sanitization

UUIDs (`uid`, `cid`), account email, sandbox hostname suffix and egress address are redacted. Raw captures retained privately.

---

## Status
VULN-01 partially patched (rollout in progress)
VULN-02 live
VULN-03 live
VULN-04 live
off-box token replay — under test
charon RPC surface (mount / snapshot / pull) — under test
*Notes, not a formal audit. Commands are reproducible; results may drift as xAI patches.*
