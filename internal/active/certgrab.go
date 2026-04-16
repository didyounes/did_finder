package active

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/yel-joul/did_finder/internal/utils"
)

// CertResult holds SSL certificate information
type CertResult struct {
	Subdomain    string   `json:"subdomain"`
	Issuer       string   `json:"issuer"`
	Subject      string   `json:"subject"`
	SANs         []string `json:"sans"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	SerialNumber string   `json:"serial_number"`
	Expired      bool     `json:"expired"`
}

// GrabCerts connects to subdomains on port 443 and extracts SSL certificate details
func GrabCerts(ctx context.Context, subdomains []string, threads int) <-chan CertResult {
	results := make(chan CertResult)
	jobs := make(chan string, len(subdomains))

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				result := grabSingleCert(sub)
				if result != nil {
					results <- *result
				}
			}
		}()
	}

	go func() {
		for _, sub := range subdomains {
			jobs <- sub
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

func grabSingleCert(subdomain string) *CertResult {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", subdomain+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	cert := certs[0]

	result := &CertResult{
		Subdomain:    subdomain,
		Issuer:       cert.Issuer.CommonName,
		Subject:      cert.Subject.CommonName,
		NotBefore:    cert.NotBefore.Format(time.RFC3339),
		NotAfter:     cert.NotAfter.Format(time.RFC3339),
		SerialNumber: fmt.Sprintf("%x", cert.SerialNumber),
		Expired:      time.Now().After(cert.NotAfter),
	}

	// Extract all SANs (Subject Alternative Names) — these reveal hidden subdomains
	for _, san := range cert.DNSNames {
		result.SANs = append(result.SANs, san)
	}

	return result
}

// ExtractSANSubdomains extracts unique subdomains found in SANs that belong to the target domain
func ExtractSANSubdomains(certResults []CertResult, domain string) []string {
	unique := make(map[string]struct{})
	for _, cr := range certResults {
		for _, san := range cr.SANs {
			san = utils.NormalizeHostname(san)
			if utils.BelongsToDomain(san, domain) {
				unique[san] = struct{}{}
			}
		}
	}

	var results []string
	for sub := range unique {
		results = append(results, sub)
	}
	return results
}
