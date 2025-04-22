package email

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// SPFCheck performs SPF verification for an incoming email
func SPFCheck(ip string, fromDomain string, helo string) (string, error) {
	resolver := &dns.Client{}
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(fromDomain), dns.TypeTXT)

	response, _, err := resolver.Exchange(message, "8.8.8.8:53")
	if err != nil {
		return "temperror", err
	}

	var spfRecord string
	for _, answer := range response.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				if strings.HasPrefix(strings.ToLower(s), "v=spf1") {
					spfRecord = s
					break
				}
			}
		}
	}

	if spfRecord == "" {
		return "none", nil
	}

	// Parse SPF record and check if IP is allowed
	return checkSPFRecord(ip, fromDomain, helo, spfRecord)
}

// checkSPFRecord evaluates an SPF record against the sender's IP
func checkSPFRecord(ip string, domain string, helo string, record string) (string, error) {
	mechanisms := strings.Fields(record)

	for _, mechanism := range mechanisms {
		if mechanism == "v=spf1" {
			continue
		}

		// Check qualifiers
		qualifier := '+'
		if len(mechanism) > 0 {
			switch mechanism[0] {
			case '+', '-', '~', '?':
				qualifier = rune(mechanism[0])
				mechanism = mechanism[1:]
			}
		}

		// Check different mechanisms
		if strings.HasPrefix(mechanism, "ip4:") {
			cidr := strings.TrimPrefix(mechanism, "ip4:")
			ipAddr := net.ParseIP(ip)

			if strings.Contains(cidr, "/") {
				_, ipnet, err := net.ParseCIDR(cidr)
				if err == nil && ipnet.Contains(ipAddr) {
					switch qualifier {
					case '+':
						return "pass", nil
					case '-':
						return "fail", nil
					case '~':
						return "softfail", nil
					case '?':
						return "neutral", nil
					}
				}
			} else {
				cidrIP := net.ParseIP(cidr)
				if cidrIP != nil && cidrIP.Equal(ipAddr) {
					switch qualifier {
					case '+':
						return "pass", nil
					case '-':
						return "fail", nil
					case '~':
						return "softfail", nil
					case '?':
						return "neutral", nil
					}
				}
			}
		} else if strings.HasPrefix(mechanism, "a") {
			// Implement "a" mechanism (domain's A record)
			mech := mechanism
			domainToCheck := domain

			if strings.Contains(mech, ":") {
				parts := strings.SplitN(mech, ":", 2)
				mech = parts[0]
				domainToCheck = parts[1]
			} else if mech != "a" {
				// Handle a/CIDR notation
				mech = "a"
			}

			ips, err := net.LookupIP(domainToCheck)
			if err != nil {
				continue
			}

			ipAddr := net.ParseIP(ip)
			for _, hostIP := range ips {
				if hostIP.Equal(ipAddr) {
					switch qualifier {
					case '+':
						return "pass", nil
					case '-':
						return "fail", nil
					case '~':
						return "softfail", nil
					case '?':
						return "neutral", nil
					}
				}
			}
		} else if strings.HasPrefix(mechanism, "mx") {
			// Implement "mx" mechanism (domain's MX records)
			mech := mechanism
			domainToCheck := domain

			if strings.Contains(mech, ":") {
				parts := strings.SplitN(mech, ":", 2)
				mech = parts[0]
				domainToCheck = parts[1]
			} else if mech != "mx" {
				// Handle mx/CIDR notation
				mech = "mx"
			}

			mxRecords, err := net.LookupMX(domainToCheck)
			if err != nil {
				continue
			}

			ipAddr := net.ParseIP(ip)
			for _, mx := range mxRecords {
				ips, err := net.LookupIP(mx.Host)
				if err != nil {
					continue
				}

				for _, hostIP := range ips {
					if hostIP.Equal(ipAddr) {
						switch qualifier {
						case '+':
							return "pass", nil
						case '-':
							return "fail", nil
						case '~':
							return "softfail", nil
						case '?':
							return "neutral", nil
						}
					}
				}
			}
		} else if mechanism == "all" {
			// "all" is a catch-all mechanism
			switch qualifier {
			case '+':
				return "pass", nil
			case '-':
				return "fail", nil
			case '~':
				return "softfail", nil
			case '?':
				return "neutral", nil
			}
		}
		// Additional mechanisms like include:, exists:, etc. would go here
	}

	// Default response if no mechanisms matched
	return "neutral", nil
}
