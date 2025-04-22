package email

import (
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DMARCPolicy represents a DMARC policy
type DMARCPolicy struct {
	Policy       string // none, quarantine, reject
	SubPolicy    string // none, quarantine, reject
	Percentage   int    // percentage of messages to apply policy to
	ReportURI    string // URI for aggregate reports
	ReportFormat string // Format for reports (default: afrf)
}

// CheckDMARC retrieves the DMARC policy for a domain
func CheckDMARC(domain string) (*DMARCPolicy, error) {
	resolver := &dns.Client{}
	message := new(dns.Msg)

	// DMARC records are located at _dmarc.domain.com
	dmarcDomain := "_dmarc." + domain
	message.SetQuestion(dns.Fqdn(dmarcDomain), dns.TypeTXT)

	response, _, err := resolver.Exchange(message, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}

	var dmarcRecord string
	for _, answer := range response.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				if strings.HasPrefix(strings.ToLower(s), "v=dmarc1") {
					dmarcRecord = s
					break
				}
			}
		}
	}

	if dmarcRecord == "" {
		// No DMARC record, use default policy
		return &DMARCPolicy{
			Policy:     "none",
			SubPolicy:  "none",
			Percentage: 100,
		}, nil
	}

	// Parse DMARC record
	return parseDMARCRecord(dmarcRecord)
}

// parseDMARCRecord parses a DMARC TXT record into a policy
func parseDMARCRecord(record string) (*DMARCPolicy, error) {
	policy := &DMARCPolicy{
		Policy:     "none",
		SubPolicy:  "none",
		Percentage: 100,
	}

	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.HasPrefix(part, "p=") {
			policy.Policy = strings.TrimPrefix(part, "p=")
		} else if strings.HasPrefix(part, "sp=") {
			policy.SubPolicy = strings.TrimPrefix(part, "sp=")
		} else if strings.HasPrefix(part, "pct=") {
			pctStr := strings.TrimPrefix(part, "pct=")
			pct, err := strconv.Atoi(pctStr)
			if err == nil && pct >= 0 && pct <= 100 {
				policy.Percentage = pct
			}
		} else if strings.HasPrefix(part, "rua=") {
			policy.ReportURI = strings.Trim(strings.TrimPrefix(part, "rua="), "\"")
		} else if strings.HasPrefix(part, "rf=") {
			policy.ReportFormat = strings.TrimPrefix(part, "rf=")
		}
	}

	// If subpolicy is not specified, it defaults to the main policy
	if policy.SubPolicy == "none" && policy.Policy != "none" {
		policy.SubPolicy = policy.Policy
	}

	return policy, nil
}

// ApplyDMARCPolicy applies DMARC policy based on SPF and DKIM results
func ApplyDMARCPolicy(fromDomain string, spfResult string, dkimResult bool) string {
	policy, err := CheckDMARC(fromDomain)
	if err != nil {
		// Error retrieving policy, default to accept
		return "accept"
	}

	// Check if random percentage requires us to skip enforcement
	if policy.Percentage < 100 {
		rand.Seed(time.Now().UnixNano())
		if rand.Intn(100) >= policy.Percentage {
			return "accept"
		}
	}

	// DMARC passes if either SPF or DKIM passes
	if spfResult == "pass" || dkimResult {
		return "accept"
	}

	// Apply policy
	switch policy.Policy {
	case "reject":
		return "reject"
	case "quarantine":
		return "quarantine"
	default:
		return "accept"
	}
}
