// Copyright (c) 2015-2024 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	// ErrInvalidWebhookScheme is returned when webhook URL uses unsupported scheme
	ErrInvalidWebhookScheme = errors.New("webhook URL must use http or https scheme")
	// ErrWebhookPrivateNetwork is returned when webhook URL targets private network
	ErrWebhookPrivateNetwork = errors.New("webhook URL cannot target private networks or localhost")
	// ErrWebhookInvalidHost is returned when webhook URL has invalid or missing host
	ErrWebhookInvalidHost = errors.New("webhook URL must have a valid host")
)

// validateWebhookURL validates that a webhook notification URL is safe to use.
// It prevents SSRF attacks by blocking:
// - Private IP ranges (RFC1918, RFC4193)
// - Loopback addresses (127.0.0.0/8, ::1)
// - Link-local addresses (169.254.0.0/16)
// - Non-HTTP(S) schemes
func validateWebhookURL(endpoint string) error {
	if endpoint == "" {
		return nil // Empty endpoint is valid (means no notification)
	}

	// Parse URL
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}

	// Only allow http and https schemes
	if u.Scheme != "http" && u.Scheme != "https" {
		return ErrInvalidWebhookScheme
	}

	// Get hostname
	hostname := u.Hostname()
	if hostname == "" {
		return ErrWebhookInvalidHost
	}

	// Block localhost by name
	if strings.EqualFold(hostname, "localhost") {
		return ErrWebhookPrivateNetwork
	}

	// Try to parse as IP first
	if ip := net.ParseIP(hostname); ip != nil {
		if isPrivateOrLocalIP(ip) {
			return ErrWebhookPrivateNetwork
		}
		return nil
	}

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		// Don't fail on DNS errors - the webhook call itself will fail
		// This prevents DoS via DNS timeouts
		return nil
	}

	// Check all resolved IPs
	for _, ip := range ips {
		if isPrivateOrLocalIP(ip) {
			return ErrWebhookPrivateNetwork
		}
	}

	return nil
}

// isPrivateOrLocalIP checks if an IP address is private, local, or otherwise restricted
func isPrivateOrLocalIP(ip net.IP) bool {
	// Loopback
	if ip.IsLoopback() {
		return true
	}

	// Link-local (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() {
		return true
	}

	// Multicast
	if ip.IsMulticast() {
		return true
	}

	// Unspecified (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return true
	}

	// Check private IPv4 ranges
	if ip.To4() != nil {
		return isPrivateIPv4(ip)
	}

	// Check private IPv6 ranges
	return isPrivateIPv6(ip)
}

// isPrivateIPv4 checks if an IPv4 address is in a private range
func isPrivateIPv4(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",        // RFC1918
		"172.16.0.0/12",     // RFC1918
		"192.168.0.0/16",    // RFC1918
		"169.254.0.0/16",    // RFC3927 (link-local, includes AWS metadata)
		"127.0.0.0/8",       // Loopback
		"224.0.0.0/4",       // Multicast
		"240.0.0.0/4",       // Reserved
		"100.64.0.0/10",     // RFC6598 (Carrier-grade NAT)
		"192.0.0.0/24",      // RFC6890 (IETF Protocol Assignments)
		"192.0.2.0/24",      // RFC5737 (Documentation)
		"198.18.0.0/15",     // RFC2544 (Benchmarking)
		"198.51.100.0/24",   // RFC5737 (Documentation)
		"203.0.113.0/24",    // RFC5737 (Documentation)
		"255.255.255.255/32", // Limited broadcast
	}

	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet != nil && subnet.Contains(ip) {
			return true
		}
	}

	return false
}

// isPrivateIPv6 checks if an IPv6 address is in a private range
func isPrivateIPv6(ip net.IP) bool {
	privateRanges := []string{
		"fc00::/7",     // RFC4193 (Unique Local Addresses)
		"fe80::/10",    // RFC4291 (Link-local)
		"::1/128",      // Loopback
		"ff00::/8",     // Multicast
		"::/128",       // Unspecified
		"::ffff:0:0/96", // IPv4-mapped IPv6
		"2001:db8::/32", // RFC3849 (Documentation)
	}

	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet != nil && subnet.Contains(ip) {
			return true
		}
	}

	return false
}
