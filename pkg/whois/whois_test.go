// tester function for whois analyzer
package whois

import (
	"strings"
	"testing"
)

// simple test for example.com
func TestWhoisGivesResults(t *testing.T) {
	want := "Internet Assigned Numbers Authority"
	result := Whois("example.com")
	matches := false
	for _, item := range result {
		if strings.Contains(item, want) {
			matches = true
		}
	}
	if matches == false {
		t.Errorf("Whois response for example.com did not contain %v", want)
	}
}

// testing for a shady domain with a single refer from IANA
func TestReferralWhoisProtocol(t *testing.T) {
	want := "Registrant Name: REDACTED FOR PRIVACY"
	result := Whois("cyber.horse")
	matches := false
	for _, item := range result {
		if strings.Contains(item, want) {
			matches = true
		}
	}
	if matches == false {
		t.Errorf("Whois response for cyber.horse did not contain %v", want)
	}
}

// testing markmonitor referral as it's different than IANA "refer"
func TestGoogleMarkMonitor(t *testing.T) {
	want1 := "Registrar URL: http://www.markmonitor.com"
	want2 := "Registrant Organization: Google LLC"
	result := Whois("google.com")
	matches := 0
	for _, item := range result {
		if strings.Contains(item, want1) {
			matches = matches + 1
		}
	}
	for _, item := range result {
		if strings.Contains(item, want2) {
			matches = matches + 1
		}
	}
	if matches < 3 {
		t.Errorf("Whois response for google.com did not contain enough of test strings")
	}
}