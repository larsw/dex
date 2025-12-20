package spnego

import (
	"context"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	dexconnector "github.com/dexidp/dex/connector"
	"github.com/jcmturner/gokrb5/v8/credentials"
	gokrbspnego "github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/krb5test"
)

const servicePrincipal = "HTTP/host.test.realm.com"

func setupKDC(t *testing.T) (*krb5test.KDC, string) {
	t.Helper()

	principals := map[string][]string{
		"testuser":       {},
		servicePrincipal: {},
	}

	kdc, err := krb5test.NewKDC(principals, log.New(io.Discard, "", log.LstdFlags))
	require.NoError(t, err)
	kdc.Start()
	t.Cleanup(kdc.Close)

	keytabBytes, err := kdc.Keytab.Marshal()
	require.NoError(t, err)

	keytabPath := filepath.Join(t.TempDir(), "service.keytab")
	require.NoError(t, os.WriteFile(keytabPath, keytabBytes, 0o600))

	return kdc, keytabPath
}

func newTestConnector(t *testing.T, keytabPath, realm string) *conn {
	t.Helper()

	cfg := Config{
		KeytabPath:       keytabPath,
		ServicePrincipal: servicePrincipal,
		Realm:            realm,
	}

	c, err := cfg.Open("spnego", slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	return c.(*conn)
}

func TestChallengeTriggersNegotiateHeader(t *testing.T) {
	kdc, keytabPath := setupKDC(t)
	conn := newTestConnector(t, keytabPath, kdc.Realm)

	req := httptest.NewRequest(http.MethodGet, "http://dex.example.com", nil)
	rec := httptest.NewRecorder()

	identity, ok, handled, err := conn.Challenge(context.Background(), dexconnector.Scopes{}, rec, req)
	require.NoError(t, err)
	require.False(t, ok)
	require.True(t, handled)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Equal(t, "Negotiate", rec.Header().Get("WWW-Authenticate"))
	require.Empty(t, identity.UserID)
}

func TestChallengeAuthenticatesUser(t *testing.T) {
	kdc, keytabPath := setupKDC(t)
	conn := newTestConnector(t, keytabPath, kdc.Realm)

	req := httptest.NewRequest(http.MethodGet, "http://dex.example.com", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	cl := kdc.Principals["testuser"].Client
	err := gokrbspnego.SetSPNEGOHeader(cl, req, servicePrincipal)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	identity, ok, handled, err := conn.Challenge(context.Background(), dexconnector.Scopes{}, rec, req)
	require.NoError(t, err)
	require.True(t, ok)
	require.False(t, handled)
	require.Equal(t, "testuser@"+kdc.Realm, identity.UserID)
	require.Equal(t, "testuser", identity.Username)
}

func TestIdentityIncludesPACGroups(t *testing.T) {
	conn := &conn{realm: "EXAMPLE.COM"}
	cred := credentials.New("user", "EXAMPLE.COM")
	cred.SetAuthenticated(true)
	cred.AddAuthzAttribute("group1")
	cred.SetAttribute(credentials.AttributeKeyADCredentials, credentials.ADCredentials{
		GroupMembershipSIDs: []string{"S-1-1-0", "group1"},
	})

	identity := conn.identityFromCredentials(cred)
	require.ElementsMatch(t, []string{"group1", "S-1-1-0"}, identity.Groups)
}
