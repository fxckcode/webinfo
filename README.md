# 🌐 webinfo

**webinfo** is a powerful command-line tool written in Go that analyzes a website's infrastructure, security, and configuration in seconds.

It combines HTTP inspection, SSL certificate analysis, technology fingerprinting, DNS lookup, and WHOIS information—all with a single command.

---

## 🚀 Features

- ✅ **HTTP status**, headers, redirects, and response time
- 🔐 **SSL/TLS certificate** details (issuer, expiration, validity)
- 🧠 **Technology detection** using [Wappalyzer](https://github.com/projectdiscovery/wappalyzergo)
- 🌐 **DNS records**: A, AAAA, MX, NS, TXT, CNAME
- 📜 **WHOIS information**: domain creation, expiration, registrar
- 💨 Fast and easy to use CLI built with [Cobra](https://github.com/spf13/cobra)

---

## 📦 Installation

### Clone and build:

```bash
git clone https://github.com/fxckcode/webinfo.git
cd webinfo
go build -o webinfo
````

### Or install with `go install`:

```bash
go install github.com/fxckcode/webinfo@latest
```

---

## 🛠️ Tech Stack

* [Go](https://golang.org/)
* [Cobra CLI](https://github.com/spf13/cobra)
* [Resty](https://github.com/go-resty/resty) - HTTP client
* [WappalyzerGo](https://github.com/projectdiscovery/wappalyzergo)
* [miekg/dns](https://github.com/miekg/dns) - DNS queries
* [likexian/whois](https://github.com/likexian/whois)
* [likexian/whois-parser](https://github.com/likexian/whois-parser)

---

## 📂 Project Structure

```
webinfo/
├── cmd/               # Cobra command setup
│   └── root.go
├── internal/
│   └── analyzer/      # HTTP, SSL, DNS, WHOIS, tech check modules
├── main.go            # CLI entry point
```

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

## 📄 License

MIT © 2025 fxckcode
