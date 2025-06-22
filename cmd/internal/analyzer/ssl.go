package analyzer

import (
    "crypto/tls"
    "fmt"
    "net"
    "net/url"
    "strings"
    "time"
)

func CheckSSL(rawurl string) {
	u, err := url.Parse(rawurl)
	if err != nil {
		fmt.Println("❌ Invalid URL:", err)
		return
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", host, nil)
	if err != nil {
		fmt.Println("❌ SSL Error:", err)
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		fmt.Println("❌ No SSL certificate found")
		return
	}

	cert := certs[0]
	fmt.Println("🔐 SSL Certificate:")
	fmt.Println("   - Issued by:", cert.Issuer.CommonName)
	fmt.Println("   - Subject:", cert.Subject.CommonName)
	fmt.Println("   - Organizations:", cert.Subject.Organization)
	fmt.Println("   - Serial number:", cert.SerialNumber)
	fmt.Println("   - Signature algorithm:", cert.SignatureAlgorithm)
	fmt.Println("   - Valid from:", cert.NotBefore)
	fmt.Println("   - Until:", cert.NotAfter)

	daysLeft := time.Until(cert.NotAfter).Hours() / 24
	fmt.Printf("   - Days remaining until expiration: %.0f days\n", daysLeft)
	if daysLeft < 30 {
		fmt.Println("⚠️ Warning: Certificate will expire soon")
	}

	if cert.IsCA {
		fmt.Println("   - Is CA (Certificate Authority)")
	}

	fmt.Println("🔗 Certificate chain:")
	for i, c := range certs {
		fmt.Printf(" Cert #%d:\n", i+1)
		fmt.Println("  - Issuer:", c.Issuer.CommonName)
		fmt.Println("  - Subject:", c.Subject.CommonName)
		fmt.Println("  - Valid from:", c.NotBefore)
		fmt.Println("  - Until:", c.NotAfter)
	}
}
