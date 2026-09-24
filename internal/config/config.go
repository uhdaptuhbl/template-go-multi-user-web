package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strconv"

	"github.com/sethvargo/go-envconfig"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/logging"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/mail"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/telemetry"
)

// Config is the complete set of settings the process runs with.
//
// Each field is the configuration type its own package defines, composed here
// rather than restated, so that adding a setting to a package does not require
// a parallel edit in this one.
type Config struct {
	// Log controls the logger's verbosity and encoding.
	Log logging.Config `env:", prefix=SERVICE_LOG_" json:"log"`
	// Server is the listener that serves users.
	Server server.Config `env:", prefix=SERVICE_SERVER_" json:"server"`
	// Admin is the listener that serves operators: metrics, health, and
	// profiling. It is a second instance of the same type rather than a
	// distinct one, because it is the same kind of thing bound elsewhere.
	Admin server.Config `env:", prefix=SERVICE_ADMIN_" json:"admin"`
	// Lifecycle sequences shutdown across both listeners. It is process-wide
	// rather than per-listener, because there is one moment at which this
	// process stops being a routing target, not one per socket.
	Lifecycle server.LifecycleConfig `env:", prefix=SERVICE_LIFECYCLE_" json:"lifecycle"`
	// Proxy describes which peers may supply forwarded request metadata. It
	// defaults to trusting nothing, so an unconfigured deployment cannot be
	// lied to about who a request came from.
	Proxy server.ProxyConfig `env:", prefix=SERVICE_PROXY_" json:"proxy"`
	// Telemetry identifies this process to a telemetry backend and says where
	// traces go. Its variables carry no project prefix; see the package doc.
	Telemetry telemetry.Config `json:"telemetry"`
	// Database is the SQL engine, its data source, and its pool limits.
	Database store.Config `env:", prefix=SERVICE_DB_" json:"database"`
	// Session is the session cookie's identity and the expiries a session is
	// subject to.
	Session session.Config `env:", prefix=SERVICE_SESSION_" json:"session"`
	// Mail is the SMTP endpoint used to deliver email one-time codes.
	Mail mail.Config `env:", prefix=SERVICE_SMTP_" json:"mail"`
	// Auth is the set of enabled authentication methods and their settings.
	Auth AuthConfig `env:", prefix=SERVICE_AUTH_" json:"auth"`
}

// errAddrVariableUnknown reports that the variable a listen address is read
// from can no longer be derived from server.Config, which happens if that
// struct's address field loses its env tag. It is a startup failure rather than
// a silent fallback, so a refactor cannot quietly turn the messages below into
// advice about a variable that does not exist.
var errAddrVariableUnknown = errors.New("cannot determine the listen address variable from server.Config")

// errOTPEnabledWithoutMail reports that email one-time codes are registered
// while mail delivery is disabled, which would register routes that could
// never send the code they promise.
var errOTPEnabledWithoutMail = errors.New("SERVICE_AUTH_OTP_ENABLED requires SERVICE_SMTP_ENABLED=true")

// errPublicOriginRequiresHTTPS reports that PublicOrigin's scheme is not
// https while the session cookie is marked Secure. A Secure cookie is never
// sent back to a plain-http origin, so the two settings together would make
// every authenticated request silently drop its session cookie.
var errPublicOriginRequiresHTTPS = errors.New("SERVICE_AUTH_PUBLIC_ORIGIN must use https when SERVICE_SESSION_COOKIE_SECURE=true")

// Validate rejects settings that are well formed but cannot be meant, which is
// the part of validation a struct tag cannot express.
//
// It is the CustomValidator hook Decode calls on the composed configuration,
// beside the hook each composed package may implement over its own settings.
// Those do not gate this one, so it checks what it reads rather than assuming
// any of them passed; tag validation does gate it, and is what guarantees the
// addresses below already split into a host and a port. Both listeners are
// checked before returning, because an operator who got one address wrong is
// likely to have got the other wrong the same way and should see both at once.
//
// It also checks the relationships between the authentication, mail, and
// session settings that span more than one of those groups, since each
// group's own hook can only see its own fields. A rule that a single group's
// hook already enforces on its own (a mail host required when mail is
// enabled, a __Host- cookie name required to be Secure) is left to that
// hook rather than duplicated here.
func (c *Config) Validate(_ context.Context) error {
	listeners, err := c.listenAddresses()
	if err != nil {
		return err
	}

	errs := make([]error, 0, len(listeners)+2)

	for _, listener := range listeners {
		errs = append(errs, checkListenPort(listener.variable, listener.addr))
	}

	if c.Auth.OTPEnabled && !c.Mail.Enabled {
		errs = append(errs, errOTPEnabledWithoutMail)
	}

	if c.Auth.PublicOrigin != "" && c.Session.CookieSecure {
		parsed, parseErr := url.Parse(c.Auth.PublicOrigin)
		if parseErr != nil || parsed.Scheme != schemeHTTPS {
			errs = append(errs, errPublicOriginRequiresHTTPS)
		}
	}

	return errors.Join(errs...)
}

// listenAddress pairs a configured listen address with the full name of the
// environment variable it was read from.
type listenAddress struct {
	variable string
	addr     string
}

// listenAddresses returns every listener composed into c, paired with the
// variable its address comes from.
//
// The names are derived from the tags that declare them, the prefix from the
// field here and the rest from server.Config, rather than written out a second
// time. Restating them would put the text an operator is told to export in two
// places at once, where renaming a prefix still compiles and only the advice
// goes stale. Deriving them also means a third listener is covered by being
// composed, with nothing to add here.
func (c *Config) listenAddresses() ([]listenAddress, error) {
	// Looked up by name because a struct tag is only reachable through the
	// type. Whether the field is missing is not checked separately: renaming it
	// breaks the build at listener.Addr below, and a zero StructField carries no
	// tag, so both failures arrive at the same guard.
	field, _ := reflect.TypeFor[server.Config]().FieldByName("Addr")

	name := envTagName(field)
	if name == "" {
		return nil, errAddrVariableUnknown
	}

	value := reflect.ValueOf(c).Elem()
	structType := value.Type()
	found := make([]listenAddress, 0, structType.NumField())

	for index := range structType.NumField() {
		composed := structType.Field(index)
		if !composed.IsExported() {
			continue
		}

		listener, ok := reflect.TypeAssert[server.Config](value.Field(index))
		if !ok {
			continue
		}

		found = append(found, listenAddress{
			variable: envTagPrefix(composed) + name,
			addr:     listener.Addr,
		})
	}

	return found, nil
}

// checkListenPort rejects port 0.
//
// Port 0 asks the kernel for an ephemeral port. That serves a test that holds
// the listener and can read the address back off it, and it cannot serve a
// deployment: no load balancer, orchestrator, or published container port can
// route to a number that only appears in a log line after the fact. Binding an
// ephemeral port from configuration is therefore always a mistake, and this is
// where it is caught. Serve still binds one when a Config is built in code.
func checkListenPort(variable, addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s: splitting host and port of %q: %w", variable, addr, err)
	}

	number, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("%s: parsing port of %q: %w", variable, addr, err)
	}

	if number == 0 {
		return fmt.Errorf("%s is %q: port 0 binds a port nothing can be told to route to; name the port the deployment publishes", variable, addr)
	}

	return nil
}

// Default returns the configuration the process runs with when nothing
// overrides it, assembled from each package's own defaults.
func Default() Config {
	return Config{
		Log:       logging.DefaultConfig(),
		Server:    server.DefaultConfig(),
		Admin:     server.DefaultAdminConfig(),
		Lifecycle: server.DefaultLifecycleConfig(),
		Proxy:     server.DefaultProxyConfig(),
		Telemetry: telemetry.DefaultConfig(),
		Database:  store.DefaultConfig(),
		Session:   session.DefaultConfig(),
		Mail:      mail.DefaultConfig(),
		Auth:      DefaultAuthConfig(),
	}
}

// Load returns the process configuration: package defaults with environment
// variables applied over them, validated.
//
// Passing nil for lookuper reads the real process environment. Tests should
// pass envconfig.MapLookuper so they neither mutate process state nor have to
// run serially.
//
// serviceVersion comes from the build rather than the environment, so it is a
// parameter rather than a field anything can set.
func Load(ctx context.Context, lookuper envconfig.Lookuper, serviceVersion string) (Config, error) {
	cfg := Default()
	cfg.Telemetry.ServiceVersion = serviceVersion

	if err := Decode(ctx, &cfg, lookuper); err != nil {
		return Config{}, fmt.Errorf("loading configuration: %w", err)
	}

	if err := cfg.Auth.LoadProviders(ctx, lookuper); err != nil {
		return Config{}, fmt.Errorf("loading configuration: %w", err)
	}

	return cfg, nil
}
