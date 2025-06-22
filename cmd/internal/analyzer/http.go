package analyzer

import (
    "fmt"
    "time"

    "github.com/go-resty/resty/v2"
)

func CheckHTTP(url string) {
	client := resty.New()
	client.SetTimeout(10 * time.Second)
	client.SetRetryCount(3)
	client.SetRetryWaitTime(2 * time.Second)
	client.SetRetryMaxWaitTime(5 * time.Second)
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(10))

	start := time.Now()
	resp, err := client.R().EnableTrace().Get(url)
	if err != nil {
		fmt.Println("❌ Error:", err)
		return
	}
	duration := time.Since(start)

	fmt.Println("✅ Status:", resp.Status(), "-", duration)
	fmt.Println("🔗 Final URL:", resp.Request.URL)

	// Show common headers
	fmt.Println("📄 Common Headers:")
	fmt.Println("   - Server:", resp.Header().Get("Server"))
	fmt.Println("   - Content-Type:", resp.Header().Get("Content-Type"))
	fmt.Println("   - Content-Security-Policy:", resp.Header().Get("Content-Security-Policy"))

	securityHeaders := []string{
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}
	fmt.Println("🔒 Security Headers:")
	for _, h := range securityHeaders {
		if val := resp.Header().Get(h); val != "" {
			fmt.Printf("   - %s: %s\n", h, val)
		}
	}

	cookies := resp.Cookies()
	if len(cookies) > 0 {
		fmt.Println("🍪 Cookies:")
		for _, c := range cookies {
			fmt.Printf("   - %s=%s; Domain=%s; Path=%s\n", c.Name, c.Value, c.Domain, c.Path)
		}
	}

	fmt.Printf("📦 Response Body Size: %d bytes\n", len(resp.Body()))

	traceInfo := resp.Request.TraceInfo()
	fmt.Println("⏱ Timing details:")
	fmt.Printf("   - DNSLookup: %v\n", traceInfo.DNSLookup)
	fmt.Printf("   - ConnTime: %v\n", traceInfo.ConnTime)
	fmt.Printf("   - TLSHandshake: %v\n", traceInfo.TLSHandshake)
	fmt.Printf("   - ServerTime: %v\n", traceInfo.ServerTime)
	fmt.Printf("   - TotalTime: %v\n", traceInfo.TotalTime)

	// Handle HTTP error codes
	if resp.StatusCode() >= 400 {
		fmt.Printf("⚠️ HTTP error detected: %d %s\n", resp.StatusCode(), resp.Status())
	}
}
