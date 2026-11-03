package db

import (
	"net"
	"strings"
)

// DeriveScopeKind decides a scope row's kind from the value itself.
//
// The caller's assetType is a hint, not a fact. Tools and agents mislabel
// assets constantly — an engagement can end up with nine hosts filed as both
// `domain` and `subdomain`, and an apex filed as a subdomain — and a boundary
// built on a wrong kind silently fails to match the host it was meant to cover.
// So the value decides, and the hint is only consulted when the value is
// genuinely ambiguous.
//
// The returned kind is one of: ip, cidr, root_domain, subdomain. An empty kind
// means the value carried nothing usable and the caller should record nothing.
func DeriveScopeKind(assetType, domain, rawURL, ip string) (kind, value string) {
	// A CIDR or a bare address is unambiguous.
	if c := strings.TrimSpace(ip); c != "" {
		if _, _, err := net.ParseCIDR(c); err == nil {
			return "cidr", c
		}
		if net.ParseIP(c) != nil {
			return "ip", ipToHostCIDR(c)
		}
	}

	// The host is whichever of the three inputs actually carries one: a URL's
	// host outranks a bare domain field only when the domain field is empty.
	host := strings.TrimSpace(domain)
	if host == "" && strings.TrimSpace(rawURL) != "" {
		host, _, _ = parseURL(normalizeURL(rawURL))
	}
	host = DomainKey(host)
	if host == "" {
		return "", ""
	}

	// An IP literal in the host field is an address, not a name.
	if net.ParseIP(host) != nil {
		return "ip", ipToHostCIDR(host)
	}

	// An apex and a subdomain are distinguished by the registrable domain, not
	// by how many labels the caller thinks it has.
	root, isApex := RootDomain(host)
	if root == "" {
		return "", ""
	}
	if isApex {
		return "root_domain", root
	}
	// A `root_domain` hint on a value that is not an apex is a mislabel; the
	// value wins, which is what keeps one host from being filed twice.
	return "subdomain", host
}
