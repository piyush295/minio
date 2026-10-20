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
	"net"
	"testing"
)

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		wantError bool
		errType   error
	}{
		// Valid cases
		{
			name:      "empty endpoint",
			endpoint:  "",
			wantError: false,
		},
		{
			name:      "valid public http",
			endpoint:  "http://example.com/webhook",
			wantError: false,
		},
		{
			name:      "valid public https",
			endpoint:  "https://webhook.example.com/notify",
			wantError: false,
		},
		{
			name:      "valid with port",
			endpoint:  "https://webhook.example.com:8443/notify",
			wantError: false,
		},
		{
			name:      "valid with query params",
			endpoint:  "https://example.com/webhook?token=abc123",
			wantError: false,
		},

		// Invalid schemes
		{
			name:      "ftp scheme",
			endpoint:  "ftp://example.com/webhook",
			wantError: true,
			errType:   ErrInvalidWebhookScheme,
		},
		{
			name:      "file scheme",
			endpoint:  "file:///etc/passwd",
			wantError: true,
			errType:   ErrInvalidWebhookScheme,
		},
		{
			name:      "gopher scheme",
			endpoint:  "gopher://localhost/",
			wantError: true,
			errType:   ErrInvalidWebhookScheme,
		},

		// Localhost
		{
			name:      "localhost by name",
			endpoint:  "http://localhost/webhook",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},
		{
			name:      "localhost case insensitive",
			endpoint:  "http://LOCALHOST/webhook",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},
		{
			name:      "loopback IPv4",
			endpoint:  "http://127.0.0.1/webhook",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},
		{
			name:      "loopback IPv4 alternate",
			endpoint:  "http://127.1.2.3/webhook",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},
		{
			name:      "loopback IPv6",
			endpoint:  "http://[::1]/webhook",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},

		// Private IPv4 ranges (RFC1918)
		{
			name:      "private 10.0.0.0/8",
			endpoint:  "http://10.0.0.1/webhook",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},
		{
			name:      "private 172.16.0.0/12",
			endpoint:  "http://172.16.0.1/webhook",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},
		{
			name:      "private 172.31.255.255",
			endpoint:  "http://172.31.255.255/webhook",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},
		{
			name:      "private 192.168.0.0/16",
			endpoint:  "http://192.168.1.1/webhook",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},

		// Link-local (AWS/GCP/Azure metadata endpoints)
		{
			name:      "AWS metadata endpoint",
			endpoint:  "http://169.254.169.254/latest/meta-data/",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},
		{
			name:      "link-local range",
			endpoint:  "http://169.254.1.1/webhook",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},

		// Carrier-grade NAT
		{
			name:      "CGN range",
			endpoint:  "http://100.64.0.1/webhook",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},

		// IPv6 private ranges
		{
			name:      "IPv6 unique local",
			endpoint:  "http://[fc00::1]/webhook",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},
		{
			name:      "IPv6 link-local",
			endpoint:  "http://[fe80::1]/webhook",
			wantError: true,
			errType:   ErrWebhookPrivateNetwork,
		},

		// Malformed URLs
		{
			name:      "no host",
			endpoint:  "http:///webhook",
			wantError: true,
		},
		{
			name:      "invalid URL",
			endpoint:  "ht!tp://example.com",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWebhookURL(tt.endpoint)
			if (err != nil) != tt.wantError {
				t.Errorf("validateWebhookURL() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if tt.errType != nil && err != tt.errType {
				t.Errorf("validateWebhookURL() error = %v, want %v", err, tt.errType)
			}
		})
	}
}

func TestIsPrivateOrLocalIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		want    bool
	}{
		// Public IPs (should return false)
		{"public IPv4", "8.8.8.8", false},
		{"public IPv4 2", "1.1.1.1", false},
		{"public IPv6", "2001:4860:4860::8888", false},

		// Loopback
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv4 loopback range", "127.255.255.254", true},
		{"IPv6 loopback", "::1", true},

		// Private IPv4
		{"10.0.0.0/8 start", "10.0.0.0", true},
		{"10.0.0.0/8 mid", "10.128.0.1", true},
		{"10.0.0.0/8 end", "10.255.255.255", true},
		{"172.16.0.0/12 start", "172.16.0.0", true},
		{"172.16.0.0/12 mid", "172.20.0.1", true},
		{"172.16.0.0/12 end", "172.31.255.255", true},
		{"192.168.0.0/16 start", "192.168.0.0", true},
		{"192.168.0.0/16 end", "192.168.255.255", true},

		// Link-local
		{"link-local start", "169.254.0.0", true},
		{"link-local AWS metadata", "169.254.169.254", true},
		{"link-local end", "169.254.255.255", true},
		{"IPv6 link-local", "fe80::1", true},

		// Carrier-grade NAT
		{"CGN start", "100.64.0.0", true},
		{"CGN end", "100.127.255.255", true},

		// IPv6 private
		{"IPv6 ULA", "fc00::1", true},
		{"IPv6 ULA 2", "fd12:3456:789a::", true},

		// Special ranges
		{"unspecified IPv4", "0.0.0.0", true},
		{"unspecified IPv6", "::", true},
		{"broadcast", "255.255.255.255", true},
		{"multicast IPv4", "224.0.0.1", true},
		{"multicast IPv6", "ff02::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("invalid test IP: %s", tt.ip)
			}
			if got := isPrivateOrLocalIP(ip); got != tt.want {
				t.Errorf("isPrivateOrLocalIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
