package ldap

// Opt-in reproduction/verification against a real Samba (or AD) DC that enforces
// LDAP channel binding. Skipped unless LDAP_CB_URL is set, so it never runs in CI
// without an explicit target and carries no embedded credentials.
//
//   LDAP_CB_URL=ldaps://dc.example.test:636 LDAP_CB_DOMAIN=example.test \
//   LDAP_CB_USER=binduser@example.test LDAP_CB_PASS='...' \
//   go test ./v3/ -run TestNTLMSASLChannelBinding_RealServer -v -count=1

import (
	"crypto/tls"
	"os"
	"testing"
)

func TestNTLMSASLChannelBinding_RealServer(t *testing.T) {
	url := os.Getenv("LDAP_CB_URL")
	if url == "" {
		t.Skip("set LDAP_CB_URL/LDAP_CB_DOMAIN/LDAP_CB_USER/LDAP_CB_PASS to run")
	}
	domain := os.Getenv("LDAP_CB_DOMAIN")
	user := os.Getenv("LDAP_CB_USER")
	pass := os.Getenv("LDAP_CB_PASS")

	dial := func() *Conn {
		c, err := DialURL(url, DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
		if err != nil {
			t.Fatalf("dial %s: %v", url, err)
		}
		return c
	}

	t.Run("correct password binds (channel binding accepted)", func(t *testing.T) {
		c := dial()
		defer c.Close()
		if err := c.NTLMSASLBind(domain, user, pass); err != nil {
			t.Fatalf("NTLMSASLBind over LDAPS still failing: %v", err)
		}
	})

	t.Run("wrong password is rejected", func(t *testing.T) {
		c := dial()
		defer c.Close()
		if err := c.NTLMSASLBind(domain, user, pass+"_wrong"); err == nil {
			t.Fatal("NTLMSASLBind accepted a wrong password")
		}
	})
}
