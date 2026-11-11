# Hades Sandbox — Architecture & Isolation Analysis

> Part 1 of 2. Companion document: [`03-findings-and-pocs.md`](./03-findings-and-pocs.md).

| | |
|---|---|
| **Target** | xAI Grok code-execution sandbox ("Hades") |
| **Component** | Guest VM, rootfs layout, control plane, network namespace |
| **Access model** | In-guest, `uid=0`, obtained via unauth control-plane (see Part 2) |
| **Class** | Architecture teardown / isolation assessment |
| **Prior art** | Supersedes the gVisor-era analysis; Hades has migrated to a microVM |

---

## 0. Scope & sanitization

All output below was collected from inside a live Hades guest. Sanitized fields: `uid`/`cid` UUIDs, account email, sandbox hostname suffix, egress address. Nothing was written to production, no customer data was read.

Out of scope: model-level behaviour, billing, `api.x.ai`, the public web tier.

---

## 1. Executive summary

Hades is no longer a gVisor container. It is a **cloud-hypervisor microVM** with a custom Rust control plane (`xai-hades-charon`) reachable over `AF_VSOCK`, a read-only erofs root, and a virtio-fs artifact channel.

The migration is a genuine hardening step and most of the classic escape surface is closed **properly** — metadata is unrouted rather than filtered, there are no cluster credentials in the guest, and the vsock listener resets rather than refuses. Disk recycling is clean.

What remains is a **control-plane trust problem, not a hypervisor problem**. The guest is treated as trusted by everything inside it: the local Node server is unauthenticated, the charon client binary is unauthenticated, and `/etc/secrets` is world-readable. The VM boundary held; the application boundary inside it did not.

Assessment: **the hypervisor boundary is sound, the intra-guest authorization boundary is absent.**

---

## 2. Methodology

1. Passive fingerprint: `/proc/cmdline`, `/proc/version`, `/sys/class/dmi/id/*`, `dmesg`, device tree, mounts, cgroup topology.
2. Capability and LSM enumeration: `capsh --print`, `/proc/self/status`, `Seccomp` fields, securebits.
3. Network mapping: routing table, `AF_INET` address tree, resolv.conf, interface list, `/proc/net/*`.
4. Cloud credential probing: IMDSv2 token flow, GCP `Metadata-Flavor`, Azure `Metadata: true`, `gke-metadata-server` fallback.
5. Orchestrator credential hunting: `serviceaccount` token paths, `docker.sock`, `containerd.sock`, cloud SDK config.
6. vsock enumeration: `AF_VSOCK` connect sweep across CID 0/1/2, ports 1–65535.
7. Storage forensics: raw `strings`/`dd` carving across `/dev/vda`, `/dev/vdb`, `/dev/vdc`, `/dev/vdd`, `/dev/nullb0`.
8. Cluster discovery: `getent hosts` against `*.svc.cluster.local`, anonymous kube API requests.
9. Component analysis: `strings` against `xai-hades-charon` and `xai-hades-styx`, subcommand enumeration.

---

## 3. Environment fingerprint

### 3.1 Host & kernel
Linux hds-<redacted> 6.12.8+ #1 SMP PREEMPT_DYNAMIC Tue Jul 21 13:56:45 UTC 2026 x86_64
Linux version 6.12.8+ (root@buildkitsandbox) (gcc 13.3.0-6ubuntu2~24.04.1)

Built in `buildkitsandbox`, x86_64, no loadable modules (`/lib/modules` absent — everything built in). Hypervisor-backed guest, not a container namespace.

### 3.2 Boot parameters

console=hvc0 quiet loglevel=3 root=/dev/vda rootfstype=erofs ro
init=/hades-container-tools/catatonit
/hades-charon/xai-hades-charon init
{"network":{"ip":"172.16.0.2/24","default_route":"172.16.0.1",
"nameserver":"172.16.0.3","hostname":"hades-vm"},
"host_aliases":[],"work_disk_device":"/dev/vdb","format_work_disk":false}
Notes:
- `console=hvc0` → virtio-console, confirms virtualised serial.
- `catatonit` as PID 1 → init shim, container-shaped process tree inside a VM.
- Charon is launched directly from the kernel command line with a JSON config argument.
- **`format_work_disk: false`** — the work disk is attached without formatting. Storage recycling depends on the host zeroing blocks; see §6.
- Guest CID is implicit; host side is CID 2.

### 3.3 Block & character devices
254:0 vda 52 MB erofs, guest rootfs, read-only
254:16 vdb 20 GB work disk, overlay upper backing
254:32 vdc 16 GB Ubuntu rootfs, app + tooling
254:48 vdd 1.9 MB erofs, /.hades-container-tools, read-only
252:0 nullb0 250 GB null_blk device
Also present: `kvm`, `fuse`, `loop-control`, `loop0-7`, `mem`, `/dev/vsock`.

`vda` and `vdd` are erofs images (compressed, read-only) — immutable by design. `vdc` is a full writable Ubuntu userland. `nullb0` is a 250 GB null_blk volume, useful as scratch.

### 3.4 Mount table
overlay / overlay rw,lowerdir=/container/root-ro,
upperdir=/work/container-root-overlay-upper,workdir=/work/container-root-overlay-work
proc /proc proc rw,nosuid,nodev,noexec
devtmpfs /dev devtmpfs rw,size=624308k,mode=755
sysfs /sys sysfs ro,nosuid,nodev,noexec
cgroup /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec
/dev/vdd /.hades-container-tools erofs ro
grok-files /home/workdir/artifacts fuse rw,nosuid,nodev,allow_other
`/container/root-ro`, `/work/container-root-overlay-*` are **host paths** referenced by the overlay but not mounted into the guest namespace — the overlay is assembled host-side. `grok-files` is a FUSE mount served by the host, the artifact egress channel.

`/dev/shm` is capped at 64 MB — tight for anything memory-backed.

### 3.5 Capabilities, seccomp, LSM
CapInh/Prm/Eff/Bnd/Amb: 000001ffffffffff (full set)
Seccomp: 2 Seccomp_filters: 1
NoNewPrivs: 1
securebits: no-new-privs=1
uid=0 euid=0 gid=0
Full capability set including `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_PTRACE`, `CAP_BPF`, `CAP_CHECKPOINT_RESTORE`. Bounding set matches, so nothing is droppable-only.

`NoNewPrivs=1` blocks setuid-based escalation — irrelevant here since the process is already `uid=0`. One seccomp filter is installed; syscall-level filtering is coarse.

No AppArmor or SELinux label applied to the workload.

### 3.6 Network
eth0 default via 172.16.0.1
eth0 172.16.0.2/24
lo 127.0.0.0/8
resolv.conf: nameserver 172.16.0.3

`172.16.0.1` and `172.16.0.3` are the VM gateway and resolver — **not** docker bridge addresses. No `ip`/`ss`/`ifconfig` in the guest; mapping done via `/proc/net/route`, `getifaddrs`, `/proc/net/tcp`.

Port sweep against `172.16.0.1`, `172.16.0.3`, `172.17.0.1` — 22/80/443/5432/6379/8000/8080/8888/9200/2375/2376/11211/27017:
172.16.0.3:53 OPEN (resolver)
everything else closed/timeout


No container runtime API, no sidecar database, no metadata proxy on the gateway. Egress to the internet is permitted (`200` from an external IP echo), so the guest is NAT'd outbound.

### 3.7 DNS

`172.16.0.3` resolves `*.svc.cluster.local`:
10.236.16.1 kubernetes.default.svc.cluster.local
Namespace `hades-openbar` is inferable from `COINGECKO_BASE_URL`, which points at `coingecko-proxy.hades-openbar.svc.cluster.local`. Cluster DNS is a free topology oracle from inside the guest.

### 3.8 Cloud metadata

All four paths fail:

| Probe | Result |
|---|---|
| `PUT 169.254.169.254/latest/api/token` (IMDSv2) | no route, exit 7 |
| `GET 169.254.169.254/latest/meta-data/*` | no route |
| `metadata.google.internal` + `Metadata-Flavor` | no route |
| `169.254.169.254/.../identity?audience=` | no route |
| Azure `Metadata: true` | no route |

`169.254.0.0/16` has no route in the guest. This is stronger than a 403-filter: there is no link-local path to any metadata service at all.

---

## 4. Component map

| Path | Component | Role |
|---|---|---|
| `/hades-charon/xai-hades-charon` | Rust binary, 6.9 MB | Control plane. Subcommands `serve`, `serve-ch-vsock`, `serve-simple`, `debug-listen-vsock`. gRPC/tonic over AF_VSOCK. |
| `/.hades-container-tools/xai-hades-styx` | Rust binary | Charon client. `exec` subcommand runs guest commands. `styx-open-to.sock` handshake. |
| `/.hades-container-tools/catatonit` | C binary | PID 1 shim. |
| `/.hades-container-tools/pyrepl.py` | Python | REPL bridge. |
| `/mnt/vdc/app/grok-computer-server.mjs` | 16.8 MB bundled JS | Node/Express server on `127.0.0.1:4242`, `X-Powered-By: Express`, reports `0.2.24`. |
| `/dev/vdc` (Ubuntu rootfs) | — | Chromium (`--no-sandbox --disable-dev-shm-usage`), npm cache, ImageMagick, full apt tree. |
| `/dev/vda` (Alpine rootfs) | — | busybox userland, `/etc/passwd`, `hades-charon` dir. |

Charon strings reveal the control-plane RPC surface and its error taxonomy, which is effectively a feature list:
HADES_GCSFUSE_MOUNT_PATH_NOT_WHITELISTED
HADES_DISK_SNAPSHOT_NOT_ALLOWED
HADES_DISK_REGISTRY_NOT_WHITELISTED
HADES_VM_SNAPSHOT_NOT_ELIGIBLE
HADES_API_KEY_NOT_WHITELISTED_FOR_INSTANCE
HADES_PODMAN_PULL_FAILED
HADES_RUNC_NOT_ALLOWED
HADES_GVISOR_NOT_ALLOWED
Implications: charon exposes VM lifecycle, snapshot, gcsfuse mount, and podman image pull. Each is gated by a whitelist or per-instance API key. **The whitelists are the attack surface** — an allowlist check that accepts a path or registry the guest supplies is a bypass candidate.

Additional strings show a `styx-open-to` socket handshake and a full `pivot_root` sequence (`/vm-tools/rw_root`, `/vm-tools/ro_root`), confirming charon is the component that assembles the guest root and pivots into it.

---

## 5. Isolation matrix

| Boundary | Control | Verdict |
|---|---|---|
| Hypervisor / host kernel | cloud-hypervisor | **Holds** — no host access achieved |
| vsock control plane | RST on every CID 2 port | **Holds** — gRPC not reachable from guest |
| Cloud metadata | no link-local route | **Holds** |
| K8s service account | no token on either rootfs | **Holds** |
| Container runtime socket | absent | **Holds** |
| Disk recycling | `format_work_disk: false` | **Holds** — carving clean |
| Cluster API | anonymous rejected | **Holds** |
| **Local Node server (4242)** | **none** | **Fails** — unauth command exec |
| **`styx exec`** | **none** | **Fails** — unauth command exec |
| **`/etc/secrets`** | **mode only** | **Fails** — world-readable credential |
| **Token lifetime** | 3600s vs ~300s VM | **Fails** — outlives the VM |
| Root filesystem | overlay, full caps | **Fails by design** — `uid=0`, writable overlay |

Six of thirteen boundaries fail. Every failure is at the **application** layer; none is at the hypervisor layer.

---

## 6. Verified negatives

Recorded so they are not re-litigated:

| Test | Result |
|---|---|
| IMDSv2 / GCP / Azure metadata | no route |
| `serviceaccount` token (4 candidate paths + `find`) | absent |
| `docker.sock`, `containerd.sock` | absent |
| vsock CID 0/1/2 sweep, ports 1–65535 | RST on all |
| `/dev/vdb` raw carve (strings, dd, JWT regex) | no foreign data |
| `/dev/vdc` dotfile/history/npm-log scan | no foreign data |
| kube API anonymous (`/version`, `/api`, `/healthz`) | rejected |
| Gateway port sweep (13 ports × 3 hosts) | only `:53` |
| `styx exec -- hostname` vs native `hostname` | identical → stays in guest |

---

## 7. Notes for defenders

1. `format_work_disk: false` is correct for latency but makes storage hygiene a host-side responsibility. The clean carve here means it is currently being honoured — that is a single configuration change away from the Cloudflare-class bug.
2. `/container/root-ro` and `/work/container-root-overlay-*` are host paths that never enter the guest namespace. Worth confirming they are not exposed by any other route.
3. The guest runs as `uid=0` with `CAP_SYS_ADMIN` and a single seccomp filter. Non-root with a tighter filter would not stop the 4242 issue, but it would blunt post-exploitation.
4. Charon's whitelist error taxonomy is a public map of its own attack surface. Assume an attacker reads those strings — they are shipped in the guest binary.
5. The control plane trusts the guest. Any RPC the guest can reach is reachable by an attacker who has `uid=0` in the guest, which — as of this writing — is anyone.

---

## Appendix A — raw output

Sanitized excerpts. Full capture retained privately.
$ capsh --print
Current: =eip
Bounding set =cap_chown,...,cap_sys_admin,cap_sys_module,cap_sys_ptrace,
cap_bpf,cap_checkpoint_restore
Securebits: 00/0x0/1'b0 (no-new-privs=1)
uid=0(root) euid=0(root)
Guessed mode: HYBRID (4)

$ grep -E 'vdb|vdc' /proc/mounts
overlay / overlay rw,relatime,lowerdir=/container/root-ro,
upperdir=/work/container-root-overlay-upper,...

$ curl -s -m 3 -X PUT http://169.254.169.254/latest/api/token
-H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
(empty) exit 7

$ python3 -c "import socket;s=socket.socket(socket.AF_VSOCK);s.settimeout(2);s.connect((2,4242))"
ConnectionResetError: [Errno 104] Connection reset by peer

$ getent hosts kubernetes.default.svc.cluster.local
10.236.16.1 kubernetes.default.svc.cluster.local

