package spnego

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

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
}

type conn struct {
	keytab   *keytab.Keytab
	logger   *slog.Logger
	settings []func(*service.Settings)
	realm    string
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

	opts := []func(*service.Settings){
		service.Logger(slog.NewLogLogger(logger.Handler(), slog.LevelInfo)),
	}

	if c.ServicePrincipal != "" {
		opts = append(opts, service.KeytabPrincipal(c.ServicePrincipal), service.SName(c.ServicePrincipal))
	}

	return &conn{
		keytab:   kt,
		logger:   logger.With(slog.Group("connector", "type", "spnego", "id", id)),
		settings: opts,
		realm:    c.Realm,
	}, nil
}

// Prompt returns an empty prompt because SPNEGO is negotiation-based.
func (c *conn) Prompt() string { return "" }

// Login is not supported because authentication is handled through SPNEGO.
func (c *conn) Login(ctx context.Context, s connector.Scopes, username, password string) (connector.Identity, bool, error) {
	return connector.Identity{}, false, errors.New("spnego connector does not support form login")
}

type responseRecorder struct {
	http.ResponseWriter
	status    int
	wroteBody bool
}

func (r *responseRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.wroteBody = true
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *responseRecorder) handled() bool {
	return r.status != 0 || r.wroteBody
}

// Challenge performs SPNEGO negotiation and returns an authenticated identity.
func (c *conn) Challenge(ctx context.Context, s connector.Scopes, w http.ResponseWriter, r *http.Request) (connector.Identity, bool, bool, error) {
	var identity connector.Identity
	var challengeErr error

	capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := goidentity.FromHTTPRequestContext(r)
		cred, ok := id.(*credentials.Credentials)
		if !ok || cred == nil || !cred.Authenticated() {
			challengeErr = errors.New("spnego: missing kerberos credentials")
			return
		}
		identity = c.identityFromCredentials(cred)
	})

	handler := gokrbspnego.SPNEGOKRB5Authenticate(capture, c.keytab, c.settings...)
	recorder := &responseRecorder{ResponseWriter: w}
	handler.ServeHTTP(recorder, r.WithContext(ctx))

	if identity.UserID != "" {
		return identity, true, recorder.handled(), nil
	}
	if challengeErr != nil {
		return connector.Identity{}, false, recorder.handled(), challengeErr
	}
	if recorder.handled() {
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
		Groups:            cred.AuthzAttributes(),
	}
}

var (
	_ connector.PasswordConnector  = (*conn)(nil)
	_ connector.ChallengeConnector = (*conn)(nil)
)
