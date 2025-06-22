package analyzer

import (
	"fmt"
	"time"
	"strings"
	"net/url"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

func CheckWHOIS(rawurl string) {
	host, err := extractHost(rawurl)
	if err != nil {
		fmt.Println("❌ Invalid URL:", err)
		return
	}

	raw, err := whois.Whois(host)
	if err != nil {
		fmt.Println("❌ WHOIS Error:", err)
		return
	}

	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		fmt.Println("❌ Parsing Error:", err)
		return
	}

	fmt.Println("📜 WHOIS info:")

	if parsed.Registrar.Name != "" {
		fmt.Println("   - Registrar:", parsed.Registrar.Name)
	}

	if parsed.Domain.CreatedDate != "" {
		if t, err := parseDate(parsed.Domain.CreatedDate); err == nil {
			fmt.Println("   - Creation date:", t.Format("2006-01-02 15:04:05"))
		} else {
			fmt.Println("   - Creation date:", parsed.Domain.CreatedDate)
		}
	}

	if parsed.Domain.ExpirationDate != "" {
		if t, err := parseDate(parsed.Domain.ExpirationDate); err == nil {
			fmt.Println("   - Expiration:", t.Format("2006-01-02 15:04:05"))
		} else {
			fmt.Println("   - Expiration:", parsed.Domain.ExpirationDate)
		}
	}

	if len(parsed.Domain.Status) > 0 {
		fmt.Println("   - Status:", strings.Join(parsed.Domain.Status, ", "))
	}

	if parsed.Registrant.Name != "" {
		fmt.Println("   - Registrant:", parsed.Registrant.Name)
	}

	if parsed.Registrant.Organization != "" {
		fmt.Println("   - Organization:", parsed.Registrant.Organization)
	}

	if len(parsed.Domain.NameServers) > 0 {
		fmt.Println("   - DNS Servers:")
		for _, ns := range parsed.Domain.NameServers {
			fmt.Println("      -", ns)
		}
	}
}

// extractHost extracts the hostname from a URL or returns the string if it's just a domain
func extractHost(rawurl string) (string, error) {
	if strings.HasPrefix(rawurl, "http://") || strings.HasPrefix(rawurl, "https://") {
		u, err := url.Parse(rawurl)
		if err != nil {
			return "", err
		}
		return u.Hostname(), nil
	}
	return rawurl, nil
}

// parseDate attempts to parse dates in common WHOIS formats
func parseDate(dateStr string) (time.Time, error) {
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"2006.01.02 15:04:05",
	}
	var t time.Time
	var err error
	for _, layout := range layouts {
		t, err = time.Parse(layout, dateStr)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, err
}
