# CVE / exploit-containment demo

The realistic finale: a real RCE lands, but the compiled,
default-deny profile blocks every *post-exploitation* step — recon, secret
theft, exfil, persistence — while the app keeps serving. This is the abstract's
threat model made visible: we don't stop the initial vector, we stop the next
step (lateral movement / escape).

There are two ways to run it: a **self-contained target** (fast, deterministic,
always works — use this live) and **real named CVEs** via vulhub (more credible
for the slide — pre-record).

---

## Option A — self-contained target (recommended for the live demo)

A tiny stdlib web app (`vulnapp.py`) with a command-injection RCE (`/run?cmd=`),
the same class as SSTI CVEs. No pip, starts instantly, profiles cleanly.

```bash
# 1. build + run the vulnerable container
docker build -t vulnapp docs/demo/cve
docker run -d --name vulnapp -p 8080:8080 vulnapp

# 2. profile its LEGIT behavior (in pane A), drive legit traffic (in pane B)
sudo ./docs/demo/profile.sh vulnapp 20                 # pane A
./docs/demo/cve/cve-demo.sh 127.0.0.1:8080 --warmup    # pane B (hits / and /health)

# 3. enforce the compiled profile (default-deny)
sudo target/release/ebpf-mon --name vulnapp --enforce docs/demo/vulnapp-events.json
#    (show --audit-only first: same run, denials only logged, nothing blocked)

# 4. attack — now contained
./docs/demo/cve/cve-demo.sh 127.0.0.1:8080
```

What the audience sees in step 4: `/` and `/health` still return 200, but
`id`, `cat /etc/shadow`, `curl <attacker>`, and dropping a backdoor all come back
CONTAINED. Why: the Python app never spawns a shell during normal work, so the
`/bin/sh` that `os.popen` needs is not in the profile → `security_bprm_check`
denies the exec; the unprofiled secret paths → `security_file_open` denies;
the unprofiled endpoint → `security_socket_connect` denies.

Reset between takes: `docker rm -f vulnapp` and rebuild.

---

## Option B — real named CVEs via vulhub (pre-record for credibility)

[vulhub](https://github.com/vulhub/vulhub) ships ready docker-compose targets.
Pick one whose post-exploit maps to our three hooks:

### Spring4Shell — CVE-2022-22965  (best fit: FILE-WRITE + EXEC)
Data-binding RCE that makes Tomcat write a **JSP webshell** to `webapps/ROOT/`,
then runs commands through it.
```bash
cd vulhub/spring/CVE-2022-22965 && docker compose up -d
# exploit writes webapps/ROOT/tomcatwar.jsp, then:  /tomcatwar.jsp?pwd=j&cmd=id
```
- **Blocked by us:** the webshell's `cmd=` spawns a shell → `bprm_check` denies;
  and the *create* of `tomcatwar.jsp` is an unprofiled open → `file_open` denies.
- Talking point: "the webshell writes, but it can't run anything."

### Log4Shell — CVE-2021-44228  (best fit: EGRESS + EXEC)
JNDI lookup → the app makes an **outbound LDAP/HTTP connection** to the
attacker, then executes a fetched payload.
```bash
cd vulhub/log4j/CVE-2021-44228 && docker compose up -d
```
- **Blocked by us:** the outbound JNDI fetch to the attacker host is an
  unprofiled endpoint → `socket_connect` denies; the second-stage payload exec →
  `bprm_check` denies. The egress block kills the exploit before stage two.

### Others that fit cleanly
- **CVE-2022-26134** (Confluence OGNL) — spawns commands → EXEC denied.
- **CVE-2017-12615** (Tomcat PUT) — writes a JSP → FILE-WRITE / EXEC denied.

For any of these: `profile.sh` the container while exercising its legit routes,
enforce, then run the public PoC and narrate which hook stops which step. Because
BPF-LSM `security_file_open` is open-granularity, lead the "blocked" narrative
with **exec** and **network** (robustly denied); treat file-write as
granularity-dependent (see `../coverage-matrix.md`).

> Only run public exploit PoCs against these throwaway containers, on a host you
> control, offline. Never point them at anything real.
