package analyzer

import (
    "fmt"
    "io"
    "net/http"
    "time"

    wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func CheckTechnologies(url string) {
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		fmt.Printf("Error creating Wappalyzer client: %v\n", err)
		return
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; WebChecker/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error making HTTP request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("⚠️ HTTP status: %d %s\n", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	fingerprints := wappalyzerClient.Fingerprint(resp.Header, body)
	if len(fingerprints) == 0 {
		fmt.Println("🤷‍♂️ No technologies detected")
		return
	}

	fmt.Println("🧠 Detected technologies:")
	for tech := range fingerprints {
		fmt.Printf("   - %s\n", tech)
	}
}
