package spnego

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/dexidp/dex/connector"
	goidentity "github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	gokrbspnego "github.com/jcmturner/gokrb5/v8/spnego"
)

// Config configures the SPNEGO connector.
type Config struct {
	// KeytabPath is the path to the service keytab containing the HTTP service principal.
	KeytabPath string `json:"keytab"`
	// ServicePrincipal optionally overrides the principal used from the keytab.
	ServicePrincipal string `json:"servicePrincipal"`
	// Realm optionally overrides the realm used when building the user identifier.
	Realm string `json:"realm"`
	// FallbackConnector optionally redirects to another connector when SPNEGO authentication is not successful.
	FallbackConnector string `json:"fallbackConnector"`
}

type conn struct {
	keytab            *keytab.Keytab
	logger            *slog.Logger
	settings          []func(*service.Settings)
	realm             string
	fallbackConnector string
}

// Open initializes the connector.
func (c *Config) Open(id string, logger *slog.Logger) (connector.Connector, error) {
	if c.KeytabPath == "" {
		return nil, errors.New("spnego: keytab path is required")
	}

	kt, err := keytab.Load(c.KeytabPath)
	if err != nil {
		return nil, fmt.Errorf("spnego: failed to load keytab: %w", err)
	}

	level := slog.LevelInfo
	if logger != nil && logger.Enabled(context.Background(), slog.LevelDebug) {
		level = slog.LevelDebug
	}
	opts := []func(*service.Settings){
		service.Logger(slog.NewLogLogger(logger.Handler(), level)),
	}

	if c.ServicePrincipal != "" {
		opts = append(opts, service.KeytabPrincipal(c.ServicePrincipal), service.SName(c.ServicePrincipal))
	}

	return &conn{
		keytab:            kt,
		logger:            logger.With(slog.Group("connector", "type", "spnego", "id", id)),
		settings:          opts,
		realm:             c.Realm,
		fallbackConnector: c.FallbackConnector,
	}, nil
}

type responseRecorder struct {
	http.ResponseWriter
	status    int
	wroteBody bool
}

func (r *responseRecorder) WriteHeader(status int) {
	if r.status != 0 {
		return
	}
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	r.wroteBody = true
	return r.ResponseWriter.Write(b)
}

func (r *responseRecorder) handled() bool {
	return r.status != 0 || r.wroteBody
}

type credentialCapture struct {
	conn     *conn
	identity connector.Identity
	err      error
}

func (c *credentialCapture) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	id := goidentity.FromHTTPRequestContext(r)
	cred, ok := id.(*credentials.Credentials)
	if !ok || cred == nil || !cred.Authenticated() {
		c.err = errors.New("spnego: missing kerberos credentials")
		return
	}
	c.identity = c.conn.identityFromCredentials(cred)
}

// Challenge performs SPNEGO negotiation and returns an authenticated identity.
func (c *conn) Challenge(ctx context.Context, s connector.Scopes, w http.ResponseWriter, r *http.Request) (connector.Identity, bool, bool, error) {
	capture := &credentialCapture{conn: c}

	handler := gokrbspnego.SPNEGOKRB5Authenticate(http.HandlerFunc(capture.ServeHTTP), c.keytab, c.settings...)
	recorder := &responseRecorder{ResponseWriter: w}
	handler.ServeHTTP(recorder, r.WithContext(ctx))

	// handled indicates the SPNEGO middleware already wrote a response (for example a 401 challenge).
	handled := recorder.handled()
	if capture.identity.UserID != "" {
		return capture.identity, true, handled, nil
	}
	if capture.err != nil {
		return connector.Identity{}, false, handled, capture.err
	}
	if handled {
		return connector.Identity{}, false, true, nil
	}

	return connector.Identity{}, false, false, nil
}

func (c *conn) identityFromCredentials(cred *credentials.Credentials) connector.Identity {
	username := cred.UserName()
	realm := cred.Domain()
	if c.realm != "" {
		realm = c.realm
	}
	userID := username
	if realm != "" {
		userID = fmt.Sprintf("%s@%s", username, realm)
	}
	preferred := userID
	if disp := cred.DisplayName(); disp != "" {
		preferred = disp
	}

	return connector.Identity{
		UserID:            userID,
		Username:          username,
		PreferredUsername: preferred,
		EmailVerified:     false,
		Groups:            cleanGroups(mergeGroups(cred)),
	}
}

func cleanGroups(groups []string) []string {
	seen := make(map[string]struct{}, len(groups))
	cleaned := make([]string, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		cleaned = append(cleaned, g)
	}
	return cleaned
}

func mergeGroups(cred *credentials.Credentials) []string {
	groups := cred.AuthzAttributes()
	ad := cred.GetADCredentials()
	if len(ad.GroupMembershipSIDs) > 0 {
		groups = append(groups, ad.GroupMembershipSIDs...)
	}
	return groups
}

func (c *conn) FallbackConnector() string {
	return c.fallbackConnector
}

var (
	_ connector.ChallengeConnector = (*conn)(nil)
)
