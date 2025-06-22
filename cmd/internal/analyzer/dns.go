package analyzer

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func CheckDNS(rawurl string) {
	host := stripURL(rawurl)
	if host == "" {
		fmt.Println("❌ Could not extract host from URL")
		return
	}

	if net.ParseIP(host) != nil {
		fmt.Println("⚠️ El host es una IP, consultas DNS limitadas.")
		return
	}

	// IPs (usamos net.LookupIP por simplicidad)
	ips, err := net.LookupIP(host)
	if err != nil {
		fmt.Println("❌ Error looking up IPs:", err)
	} else if len(ips) == 0 {
		fmt.Println("⚠️ No IPs found for", host)
	} else {
		fmt.Println("🌐 IPs:")
		for _, ip := range ips {
			fmt.Println("   -", ip.String())
		}
	}

	// Consultas DNS avanzadas
	queryAandAAAA(host)
	queryCNAME(host)
	queryMX(host)
	queryNS(host)
	queryTXT(host)
}

func stripURL(rawurl string) string {
	host := rawurl
	if strings.HasPrefix(rawurl, "http") {
		u, err := url.Parse(rawurl)
		if err != nil {
			return ""
		}
		host = u.Hostname()
	}
	return host
}

func queryAandAAAA(host string) {
	c := new(dns.Client)
	m := new(dns.Msg)

	// A
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	start := time.Now()
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	elapsed := time.Since(start)
	if err != nil {
		fmt.Println("❌ Error querying A records:", err)
	} else if len(r.Answer) == 0 {
		fmt.Println("⚠️ No A records found")
	} else {
		fmt.Printf("📶 A Records (⏱️ %s):\n", elapsed)
		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				fmt.Printf("   - %s\n", a.A.String())
			}
		}
	}

	// AAAA
	m.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
	start = time.Now()
	r, _, err = c.Exchange(m, "8.8.8.8:53")
	elapsed = time.Since(start)
	if err != nil {
		fmt.Println("❌ Error querying AAAA records:", err)
	} else if len(r.Answer) == 0 {
		fmt.Println("⚠️ No AAAA records found")
	} else {
		fmt.Printf("📶 AAAA Records (⏱️ %s):\n", elapsed)
		for _, ans := range r.Answer {
			if aaaa, ok := ans.(*dns.AAAA); ok {
				fmt.Printf("   - %s\n", aaaa.AAAA.String())
			}
		}
	}
}

func queryCNAME(host string) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeCNAME)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		fmt.Println("❌ Error querying CNAME record:", err)
		return
	}
	for _, ans := range r.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			fmt.Println("🔗 CNAME:", cname.Target)
		}
	}
}

func queryMX(host string) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeMX)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		fmt.Println("❌ Error querying MX records:", err)
		return
	}
	if len(r.Answer) == 0 {
		fmt.Println("⚠️ No MX records found")
		return
	}
	fmt.Println("📧 MX Records:")
	for _, ans := range r.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			fmt.Printf("   - %s (Priority: %d)\n", mx.Mx, mx.Preference)
		}
	}
}

func queryNS(host string) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeNS)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		fmt.Println("❌ Error querying NS records:", err)
		return
	}
	if len(r.Answer) == 0 {
		fmt.Println("⚠️ No NS records found")
		return
	}
	fmt.Println("📚 NS Records:")
	for _, ans := range r.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			fmt.Printf("   - %s\n", ns.Ns)
		}
	}
}

func queryTXT(host string) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeTXT)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		fmt.Println("❌ Error querying TXT records:", err)
		return
	}
	if len(r.Answer) == 0 {
		fmt.Println("⚠️ No TXT records found")
		return
	}
	fmt.Println("📝 TXT Records:")
	for _, ans := range r.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			fmt.Printf("   - %s\n", strings.Join(txt.Txt, " "))
		}
	}
}
