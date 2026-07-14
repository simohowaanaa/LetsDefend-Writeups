# 🔐 Http Basic Auth. — LetsDefend Challenge

| | |
|---|---|
| **Platform** | [LetsDefend](https://app.letsdefend.io/challenge/http-basic-auth) |
| **Category** | Network Forensics |
| **Difficulty** | Easy |
| **Status** | ✅ Solved (7/7) |

---

## 🎯 Scenario

> We receive a log indicating a possible attack, can you gather information from the .pcap file?

- **File location:** `/root/Desktop/ChallengeFile/webserver.em0.pcap`

---

## 🧰 Tools used

- **Wireshark** — packet capture analysis
- Follow HTTP Stream, display filters, Base64 decoding

---

## 🔬 Analysis workflow

### 1. Count HTTP GET requests (Q1)
Filtering the capture:

```
http.request.method == "GET"
```

returns **5** GET requests (see `Displayed` count in the status bar).

![GET requests](screenshots/01-get-requests.png)

### 2. Read server & client info from the HTTP stream (Q2–Q5)
`Right-click a GET packet > Follow > HTTP Stream` exposes the request and response
headers:

```
User-Agent: Lynx/2.8.7rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8n

HTTP/1.1 401 Authorization Required
Server: Apache/2.2.15 (FreeBSD) DAV/2 mod_ssl/2.2.15 OpenSSL/0.9.8n
WWW-Authenticate: Basic realm="Restricted"
```

- **OS:** `FreeBSD` (also hinted by the `em0` interface name in the filename)
- **Web server:** `Apache/2.2.15`
- **OpenSSL:** `OpenSSL/0.9.8n`
- **Client User-Agent:** `Lynx/2.8.7rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8n`

![HTTP stream](screenshots/02-http-stream.png)

### 3. Extract Basic Auth credentials (Q6, Q7)
The first request returns `401`; the client then retries with an `Authorization`
header. Filtering for it:

```
http.authorization
```

The request carries `Authorization: Basic d2ViYWRtaW46VzNiNERtMW4=`. Basic Auth
only **Base64-encodes** the credentials, so they decode trivially:

```bash
echo -n "d2ViYWRtaW46VzNiNERtMW4=" | base64 -d
# webadmin:W3b4Dm1n
```

- **Username:** `webadmin`
- **Password:** `W3b4Dm1n`

![Basic Auth header](screenshots/03-basic-auth.png)

---

## ❓ Questions & Answers

| # | Question | Answer |
|---|----------|--------|
| 1 | How many HTTP GET requests are in the pcap? | `5` |
| 2 | What is the server operating system? | `FreeBSD` |
| 3 | Name and version of the web server software? | `Apache/2.2.15` |
| 4 | Version of OpenSSL running on the server? | `OpenSSL/0.9.8n` |
| 5 | Client's user-agent information? | `Lynx/2.8.7rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8n` |
| 6 | Username used for Basic Authentication? | `webadmin` |
| 7 | Password used for Basic Authentication? | `W3b4Dm1n` |

---

## 📝 Summary / Lessons learned

- **HTTP headers are a goldmine.** The `Server:` header leaks the OS, web server
  version, and OpenSSL version — valuable recon for an attacker.
- **HTTP Basic Auth over cleartext is unsafe.** Credentials are only Base64-encoded,
  not encrypted. Anyone capturing the traffic recovers `webadmin:W3b4Dm1n` instantly.
- **Follow HTTP Stream** reconstructs full request/response exchanges.
- The `http.authorization` filter quickly isolates authenticated requests.
- **Remediation:** always serve authentication over **HTTPS/TLS**, and prefer
  token-based auth over Basic Auth.

### Indicators / Artifacts

| Type | Value |
|------|-------|
| Web server | `192.168.63.100` — Apache/2.2.15 (FreeBSD), OpenSSL/0.9.8n |
| Client | `192.168.63.20` — Lynx browser |
| Credentials (leaked) | `webadmin:W3b4Dm1n` |
