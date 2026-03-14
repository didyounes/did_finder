package active

import (
	"fmt"
	"net"
	"strings"
)

// ZoneTransfer attempts AXFR zone transfer against the NS records of the domain
func ZoneTransfer(domain string) ([]string, error) {
	var results []string

	// Look up NS records
	nsRecords, err := net.LookupNS(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup NS records: %w", err)
	}

	for _, ns := range nsRecords {
		nsHost := strings.TrimSuffix(ns.Host, ".")

		// Try TCP connection to nameserver port 53
		conn, err := net.Dial("tcp", nsHost+":53")
		if err != nil {
			continue
		}

		// Build AXFR query manually
		// Transaction ID
		query := []byte{
			0x00, 0x01, // Transaction ID
			0x00, 0x00, // Flags (standard query)
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answers: 0
			0x00, 0x00, // Authority: 0
			0x00, 0x00, // Additional: 0
		}

		// Encode domain name
		parts := strings.Split(domain, ".")
		for _, part := range parts {
			query = append(query, byte(len(part)))
			query = append(query, []byte(part)...)
		}
		query = append(query, 0x00) // Root label

		// AXFR type (252) and IN class (1)
		query = append(query, 0x00, 0xFC) // Type AXFR
		query = append(query, 0x00, 0x01) // Class IN

		// TCP DNS messages are prefixed with 2-byte length
		length := len(query)
		tcpQuery := append([]byte{byte(length >> 8), byte(length & 0xFF)}, query...)

		_, err = conn.Write(tcpQuery)
		if err != nil {
			conn.Close()
			continue
		}

		// Read response
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		conn.Close()

		if err != nil || n < 12 {
			continue
		}

		// Skip TCP length prefix
		if n > 2 {
			response := string(buf[2:n])
			// Try to extract subdomains from raw response
			for _, part := range strings.Split(response, "."+domain) {
				// Look for valid subdomain patterns before the domain
				sub := extractLastLabel(part)
				if sub != "" && isValidLabel(sub) {
					full := sub + "." + domain
					results = append(results, full)
				}
			}
		}
	}

	return results, nil
}

func extractLastLabel(s string) string {
	// Find the last readable label in binary data
	var label []byte
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			label = append([]byte{c}, label...)
		} else {
			break
		}
	}
	result := strings.Trim(string(label), ".-")
	return result
}

func isValidLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
