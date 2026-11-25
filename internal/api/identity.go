package api

import "strings"

// DomainAllowed decides whether a verified identity belongs to the allowed
// domain. Google sets the hd claim only for Workspace accounts; a consumer
// account can carry a verified address of the company domain, so for Google
// hd must match. Other providers are checked by hd or the email domain.
func DomainAllowed(issuer, email, hd, domain string) bool {
	if domain == "" {
		return true
	}
	if strings.TrimRight(issuer, "/") == "https://accounts.google.com" {
		return strings.EqualFold(hd, domain)
	}
	return strings.EqualFold(hd, domain) || strings.HasSuffix(strings.ToLower(email), "@"+strings.ToLower(domain))
}
