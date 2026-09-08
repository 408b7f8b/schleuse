# schleuse — reverse tunnel for Linux devices

[Deutsch](README.md) · **English**

Reach devices behind NAT and firewalls without opening a port there. The device
itself opens an outbound TLS connection to a relay on the internet; over that
same connection SSH, SCP, HTTP or any other TCP protocol is passed through on
demand.

A new device enrolls itself with a single command, lands in a queue and is
approved in the browser. One binary, no runtime dependencies.

```
       Plant network                         Internet                  Operator

  ┌──────────────────────┐                                     ┌──────────────────────┐
  │ werk1-hmi            │                                     │  one schleuse client │
  │   sshd :22           │                                     │                      │
  │   httpd :80          │                                     │  :2201 → werk1/ssh   │
  │   schleuse agent ────┼───┐                                 │  :8001 → werk1/http  │
  └──────────────────────┘   │                                 │  :2202 → werk2/ssh   │
                             │         ┌───────────────────┐   │  :5021 → werk2/mb    │
  ┌──────────────────────┐   │         │       relay       │   │                      │
  │ werk2-hmi            │   ├────────▶│  :443   tunnel    │◀──┤  all at once         │
  │   sshd, httpd,       │   │ outbound│  self-enrollment  │   └──────────────────────┘
  │   modbus :502        │   │   TLS   │  :8443 web UI     │
  │   schleuse agent ────┼───┘         └─────────▲─────────┘
  └──────────────────────┘                       │ password + 2FA
                                                 │
  ┌──────────────────────┐             ┌─────────┴─────────┐
  │ new device           │  request    │       queue       │
  │   schleuse enroll ───┼────────────▶│                   ├─── approve ──▶ in service
  └──────────────────────┘             └───────────────────┘

        no open port                   the only open port         no open port
                                       for devices                (loopback only)
```

Any number of devices, each with any number of services, all at the same time.
Every single user session gets its own TLS connection from the device to the
relay — two sessions share no buffer, no state and no ordering.

## Connecting a new device

On the device, once — **the same line for every device in the plant, it contains
no secret** and may sit in the provisioning script:

```sh
schleuse enroll -relay tunnel.example.com:443 -ca-pin PGVZ-4CT3-JUFW-E3RD \
            -service ssh=127.0.0.1:22 -service http=127.0.0.1:80
```

```
Antrag gestellt. Das Gerät wartet auf die Freigabe.

    Fingerabdruck   3K25-4FIL-6UI3-QDWD

Diesen Fingerabdruck in der Weboberfläche des Relays vergleichen,
bevor freigegeben wird.
```

While it waits, the device has **no certificate**, appears in no device list and
reaches nothing. The request shows up in the web UI with the same fingerprint;
if the two match, nobody swapped anything in transit. The operator assigns a
name and the permitted services and approves — only then does a certificate come
into being, which the device picks up on its next poll before going into
service.

The private key is generated on the device and never leaves it.

## Why it is built this way

The core of the design is that **nobody except the relay has a port on the
internet** and **the relay cannot initiate anything on its own**. It only
mediates between an enrolled device and an authorised operator.

There is deliberately no multiplexing protocol over a single connection.
Instead the agent holds one long-lived control channel and opens **its own
outbound TLS connection per session**. That costs one round trip at connection
setup and saves an entire layer: no window management of our own, no
head-of-line blocking, no buffer state to get wrong. The kernel does the flow
control.

## Security model

| | |
|---|---|
| **Transport** | TLS 1.3, no older versions, no downgrade negotiation |
| **Authentication** | mutual (mTLS) against a private CA — the device checks the relay too |
| **Identity** | lives in the certificate CN: `device:werk1-hmi`, `client:db`. A device cannot claim to be another one, because the configuration is not consulted for this |
| **Two CAs** | The root CA stays offline and signs relay and operator certificates. The relay only holds an intermediate CA for devices. **The relay accepts operator certificates only if the root CA signed them directly** — taking over the relay grants no access |
| **First contact** | The device does not know the CA yet and checks the relay against the fingerprint from its configuration **before** the certificate request leaves the device |
| **Quarantine** | A newly enrolled device has no certificate and reaches nothing until a human approves it and compares the key fingerprint |
| **Device list** | Only what is listed in `acl.json` may enrol. If the list is missing entirely, enrolment is open to every certificate of the CA — the relay warns about this at startup |
| **Authorisation** | Which operator may reach which devices and services; patterns such as `werk1-*` are allowed |
| **Release at the device** | The agent only connects to targets from its own service table. The relay knows service names, never addresses — it can grant and revoke, but cannot point a device at arbitrary addresses in the plant network |
| **Device separation** | Streams are tracked per device session and requested via a 128-bit random id. A device cannot pick up another device's stream — the lookup goes through its certificate, not the id alone |
| **Operator separation** | Two budgets per device: one for all sessions together, a tighter one per operator |
| **Visibility** | `schleuse client -list` and the web UI show each party only what it may reach |
| **Revocation** | An entry in `acl.json` or a click in the UI. Takes effect immediately — **running** sessions are cut as well |
| **Web UI** | Its own port with its own certificate. Username, password (PBKDF2-HMAC-SHA256, 600,000 rounds) and a second factor (TOTP). Sessions in memory, a fresh id after every login step, a token against cross-site forms on every change, lockout after five failed attempts, no JavaScript and a content policy that enforces it |
| **API** | Tokens with 256 random bits, shown once, stored as SHA-256, with a role and an expiry. Without a valid token **every** path answers the same: 404, empty body, no `WWW-Authenticate`. No path listing, no description, no Swagger. A session cookie does not count as a token — otherwise a link sent to a logged-in administrator would be enough for a hostile page |
| **Confidentiality towards the relay** | SSH and HTTPS are end-to-end encrypted; the relay sees ciphertext only |
| **Memory** | Transfer buffers are cleared before being handed to the next session |
| **Privileges** | Both services run as their own user without capabilities, with `MemoryDenyWriteExecute` and `SystemCallFilter` |

The relay is therefore a *broker, not a trust anchor*: whoever takes it over can
refuse connections, see metadata and issue device certificates — but can neither
impersonate an operator nor read SSH traffic.

The configuration is parsed strictly: a typo in `services` or `devices` aborts
the start instead of silently becoming an empty list.

## Building

```sh
./build.sh                       # for the local architecture
./build.sh linux-x64 linux-arm64 # several targets
```

Result: `out/<rid>/schleuse`, about 12 MB. No .NET runtime is needed on the
target device. Cross-building for another architecture needs `clang`; if it is
missing, `build.sh` falls back on its own to a self-contained single-file bundle
(about 20 MB, likewise running without a pre-installed runtime). The same
applies to 32-bit ARM, for which there is no Native AOT. Such a bundle carries
a JIT and therefore cannot run with `MemoryDenyWriteExecute=yes` — that line
then has to come out of the systemd unit.

## Setting up

**1 — CAs** (on a secure machine, not on the relay):

```sh
./scripts/schleuse-pki.sh init                     # root CA, stays here
./scripts/schleuse-pki.sh device-ca                # intermediate CA for self-enrolment
./scripts/schleuse-pki.sh relay tunnel.example.com
./scripts/schleuse-pki.sh client db
```

`pki/ca.key` stays there and is copied nowhere. Only `ca.crt`, `relay.crt`,
`relay.key`, `device-ca.crt` and `device-ca.key` go to the relay.

**2 — Relay:**

```sh
install -m755 out/linux-x64/schleuse /usr/local/bin/schleuse
useradd --system --no-create-home --shell /usr/sbin/nologin schleuse
install -d -m750 -o root -g schleuse /etc/schleuse
install -m640 -o root -g schleuse ca.crt relay.crt relay.key device-ca.crt device-ca.key /etc/schleuse/
cp examples/relay.json /etc/schleuse/           # and adjust
cp deploy/schleuse-relay.service /etc/systemd/system/
systemctl enable --now schleuse-relay
```

For the web UI a publicly trusted certificate is advisable so the browser does
not warn:

```sh
certbot certonly --standalone -d tunnel.example.com
# enter the paths in relay.json under "web"
```

At startup the log states the setup password for the first administrator and the
CA fingerprint for self-enrolment:

```
warn  web    noch kein Benutzer eingerichtet. Zum Anlegen des ersten Verwalters:
warn  web        https://tunnel.example.com:8443/setup   Kennwort: QID47-SXOJZ-...
info  relay  CA-Fingerabdruck fuer 'schleuse enroll': PGVZ-4CT3-JUFW-E3RD
```

**3 — Devices:** see [Connecting a new device](#connecting-a-new-device). After
approval:

```sh
cp deploy/schleuse-agent.service /etc/systemd/system/
systemctl enable --now schleuse-agent
```

**4 — Operators:** `ca.crt`, `client-db.crt`, `client-db.key` and `client.json`
into `~/.config/schleuse/`.

## Managing in the browser

The UI works without JavaScript and does five things:

* **Overview** — what is connected, what is running right now.
* **Queue** — new requests with a fingerprint to compare, assign name and
  permitted services, approve or reject.
* **Devices** — note, released services, revoke, remove. Which address sits
  behind a service name remains the device's decision; here it is only granted
  or revoked.
* **Access** — who may reach which devices and services. The matching
  certificates are created offline, not here.
* **Users** — administrators and read-only accounts, reset password and second
  factor.
* **API** — issue and withdraw tokens.

Every user needs a password and a second factor. On first login the secret for
the authenticator app is shown as a QR code, below it in Base32 for typing and
as a complete `otpauth://` line — not every app can scan, and whoever has the
code on the same screen as the app needs the text. Eight recovery codes come
with it, each valid once.

The QR code is generated in the service and sits in the document as SVG. No
encoding service on the net: the line contains the second-factor secret, sending
it to a stranger would defeat the whole exercise. No externally loaded image:
this keeps the UI's content policy at `default-src 'none'`.

## Managing programmatically

Every function of the UI also exists as a call. Authentication uses a token
created either in the UI or through the API itself:

```sh
T=schleuse_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
B=https://tunnel.example.com:8443/api

curl -H "Authorization: Bearer $T" $B/status
curl -H "Authorization: Bearer $T" $B/pending

curl -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
     -d '{"id":"a1b2…","device":"werk3-hmi","note":"Halle 3","services":["ssh","http"]}' \
     $B/pending/approve
```

| Reading (`GET`) | |
|---|---|
| `/status` | overview, CA fingerprint, running sessions |
| `/devices` | device list with online state and releases |
| `/pending` | queue with fingerprints |
| `/clients` | access entries and their patterns |
| `/users` | users of the UI (without secrets) |
| `/tokens` | issued tokens (never in clear text) |

| Changing (`POST`, admin token only) | Fields |
|---|---|
| `/pending/approve` | `id`, `device`, `note`, `services[]` |
| `/pending/reject`, `/pending/delete` | `id` |
| `/devices/save` | `device`, `note`, `services[]`, `revoked` |
| `/devices/delete` | `device` |
| `/clients/save` | `client`, `devices[]`, `services[]`, `revoked` |
| `/clients/delete` | `client` |
| `/users/add` | `user`, `role` → returns the initial password once |
| `/users/delete` | `user` |
| `/users/reset` | `user`, `what` = `password` \| `2fa` |
| `/tokens/create` | `name`, `role`, `days` → returns the token once |
| `/tokens/delete` | `id` |
| `/ui` | `enabled` — turns the web UI off or on |

A token with the role `viewer` may only read; a write attempt gets `403`. A path
that does not exist gets `404` — exactly like every path without a token, so the
API cannot be probed.

**Turning the UI off.** For anyone who wants to run administration purely
programmatically after setup:

```sh
curl -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
     -d '{"enabled":false}' $B/ui
```

After that the port answers every UI path with 404, as if it did not exist; the
API stays reachable and can switch it back on. If the token is lost, on the
relay:

```sh
schleuse ui -c /etc/schleuse/relay.json -on
systemctl reload schleuse-relay
```

The prefix of all paths is freely selectable via `web.api_path`. A value that
cannot be guessed keeps casual probing away — the actual protection is and
remains the token.

## Using

**What is reachable right now?**

```sh
$ schleuse client -list
GERAET                   DIENSTE                             ONLINE  SITZUNGEN
pumpstation-nord         ssh                                     3s          0
werk1-hmi                http,ssh                                2s          0
werk2-hmi                http,modbus,ssh                         3s          0
```

A different account sees something different in the same place.

**Several devices and protocols in one process:**

```sh
schleuse client -forward werk1-hmi/ssh=127.0.0.1:2201 \
            -forward werk1-hmi/http=127.0.0.1:8001 \
            -forward werk2-hmi/ssh=127.0.0.1:2202 \
            -forward werk2-hmi/modbus=127.0.0.1:5021

ssh  -p 2201 root@127.0.0.1
curl http://127.0.0.1:8001/
```

If the forwards are listed under `forwards` in `~/.config/schleuse/client.json`,
plain `schleuse client` is enough.

For the local ports, `/proc/sys/net/ipv4/ip_local_port_range` (typically
32768–60999) is worth a look: putting a forward inside that range occasionally
yields "Address already in use", because an outgoing connection has just taken
the same port as its source port. Values below are unobtrusive.

**A single one:**

```sh
schleuse client -device werk1-hmi -service ssh -listen 127.0.0.1:2222
scp -P 2222 firmware.bin root@127.0.0.1:/tmp/
```

**Without an open port, as a ProxyCommand** — the cleanest way for SSH:

```
Host werk1-hmi werk2-hmi pumpstation-nord
    ProxyCommand schleuse client -device %h -service ssh -stdio
    User root
```

After that `ssh werk1-hmi` and `scp file werk2-hmi:/tmp/` are enough.

## Extending

Another protocol is one entry in the device's `services`:

```json
"services": {
  "ssh":    "127.0.0.1:22",
  "modbus": "192.168.10.5:502",
  "opcua":  "192.168.10.7:4840",
  "vnc":    "127.0.0.1:5900"
}
```

The target need not live on the device: `192.168.10.5:502` turns the device into
a controlled entry point into its plant network — but only to exactly that
address. Self-enrolment can carry this along right away (`-service …`); in the
UI the service is then merely released.

## Testing

Five suites, all runnable without preparation — they build themselves CAs,
relay, devices and operators in a temporary directory:

```sh
./build.sh
./out/linux-x64/schleuse verify-crypto   # 186 test vectors from the specifications
./scripts/selftest.sh                # 22 checks: does it do what it should
./scripts/securitytest.sh            # 24 checks: does it refuse what it must refuse
./scripts/multitest.sh               # 19 checks: several devices, parallel, separated
./scripts/webtest.sh                 # 39 checks: UI and self-enrolment
./scripts/apitest.sh                 # 44 checks: API and its discretion
./scripts/sbom.sh                    # bill of materials in CycloneDX format
```

`verify-crypto` recomputes TOTP against RFC 6238, Base32 against RFC 4648 and
PBKDF2 against RFC 6070 — hand-written crypto building blocks that merely look
plausible are the most common cause of silent security holes. Plus the QR
encoder against ISO/IEC 18004: for each of the forty versions the two edge
lengths, and the whole grid as a checksum each time.

These checksums do not come from schleuse itself — otherwise the encoder would
be checking itself. They come from `scripts/qr-gegenpruefen.py`, which puts the
encoder up against independent implementations: nearly a thousand inputs across
the whole range, module by module against the `qrcode` library, the mask choice
against the standard's penalty terms recomputed independently, and every
generated code decoded again once with `zxing-cpp`. The script needs additional
packages and therefore does not run in the suites; it is needed when changing
the encoder.

`webtest.sh` plays through the whole path: initial setup, second factor, login,
a device enrols itself, waits, is approved, fetches its certificate and then
carries a tunnel. In between: access without a session, a form with a wrong
token, a read-only role, lockout after five failed attempts, fingerprint
comparison between device and UI.

`apitest.sh` checks that nothing can be learned without a token (not even under
`/openapi`, `/swagger` or `/docs`), that a session cookie does not count as a
token, that a read-only token cannot change anything, that the whole path from
self-enrolment to tunnel also works programmatically, and that the UI can be
switched off and on again.

`KEEP=1` before the call keeps the working directory including logs for
inspection.

## Measured

Native AOT binary, x86-64, all roles on one machine over loopback:

| | |
|---|---|
| Binary | 12 MB, no runtime dependency |
| Startup time | 3.2 ms |
| Memory, relay and agent each | 14 MB RSS when idle |
| Relay with 50 enrolled devices | 23 MB RSS, 1.7 % CPU — about 190 kB per device |
| HTTP throughput through the tunnel | 439 MB/s (50 MB, three TLS legs in a row) |
| 100 requests, 50 concurrent | all with 200 in 0.7 s |

### How big does the relay have to be?

Measured with the relay alone, under load from simulated devices and held
tunnels; for the core test pinned to a single core:

| | |
|---|---|
| Base demand | 20 MB RSS |
| per enrolled device | **about 200 kB** (300 devices: 73 MB, 2.7 % of a core) |
| per concurrent tunnel | **about 300 kB** (250 tunnels: 95 MB, 4.2 % of a core) |
| Connection setups | about 1,500/s at half the load of one core |
| Throughput on one core | 673 MB/s |

Hence the rule of thumb:

    RAM ≈ 25 MB + 0.2 MB × devices + 0.3 MB × concurrent tunnels + headroom

A plant with 50 devices and five concurrent sessions therefore needs about
40 MB. Even 500 devices with 50 sessions stay below 150 MB.

**Recommendation: 1 vCore and 1 GB RAM are enough well into the range of a few
hundred devices.** Two cores and 2 GB are the comfortable choice when more than
a thousand devices come together, when many firmware transfers regularly run at
once, or when something else lives on the same machine. At 1 GB a swap file
belongs with it.

The measurements come from a workstation; a vCore at a provider is two to four
times slower. Even then several hundred connection setups per second remain, and
a throughput far above what the line delivers — 1 Gbit/s is 125 MB/s.

**The cost driver is therefore not compute or memory, but the traffic passed
through.** Every byte runs through the relay. When comparing offers, the
included volume counts, not the number of cores.

**Trying it out works without a provider.** A systemd scope locks the whole test
environment into the limits of a small VM:

```sh
systemd-run --user --scope -p CPUQuota=200% -p MemoryMax=2G \
    ./scripts/multitest.sh
```

All five suites run through inside it — relay, three agents, six forwards and
six test servers together — with a memory peak of 143 MB and 19 seconds of CPU
time. On a real machine only the relay lives there.

Two adjustment screws in case it does get tight: the transfer buffers are 64 kB
per direction (`Pump.BufferSize`) and make up the lion's share of the 300 kB per
tunnel; and memory is returned to the operating system only slowly after load
peaks, so the numbers above are peaks, and peaks are what to size for.

## Limits

* **A local port is open to everyone on the machine.** Whoever can log in to the
  operator's laptop can use the configured forwards too — that holds for every
  port forward, `ssh -L` included. Where that matters, `-stdio` is the way.
* **Operator certificates are created offline.** The UI manages authorisations
  but issues nothing — deliberately, because the intermediate CA on the relay
  may only certify devices.
* **UDP is not tunnelled.** The tunnel is TCP.
* **The device's clock has to be roughly right.** On hardware without a
  battery-backed clock, NTP belongs before the schleuse service.
* **Certificates expire** (devices 825 days, operators 365). There is no
  automatic renewal; `schleuse-pki.sh list` shows the remaining lifetimes.
* **The relay is a single point of failure.** It keeps its state in a few JSON
  files; a second relay is quickly set up, but the agents know only one address.
* **Two agents with the same certificate displace each other.** Every device
  needs its own.

## Source layout

| File | Content |
|---|---|
| `src/Protocol.cs` | Wire format: line-based JSON for handshake and control, raw bytes afterwards |
| `src/Tls.cs` | mTLS, validation against our own CA, identity and issuer from the certificate |
| `src/Relay.cs` | Brokering, device registry, access list, acceptance of requests |
| `src/Agent.cs` | Enrolment, reconnect, service release |
| `src/Client.cs` | Forwards, ProxyCommand mode, overview |
| `src/Enrollment.cs` | Queue and issuance of device certificates |
| `src/EnrollClient.cs` | `schleuse enroll` on the device |
| `src/WebUi.cs`, `src/WebUiSeiten.cs` | Web UI |
| `src/WebApi.cs`, `src/ApiTypes.cs`, `src/ApiTokens.cs` | API, data shapes, tokens |
| `src/Users.cs`, `src/Passwords.cs`, `src/Totp.cs` | Users, passwords, second factor |
| `src/Pump.cs` | Bidirectional copying with correct half-close |
| `src/Config.cs` | Configuration, access list, glob patterns |

Alongside: [SECURITY.md](SECURITY.md) with the reporting path, support period,
logging and deletion procedure, [TODO.md](TODO.md) with the open points, plus
`sbom.cdx.json` as the bill of materials.
