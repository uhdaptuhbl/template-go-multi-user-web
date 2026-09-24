package mail

import (
	"context"
	"errors"
	"fmt"

	gomail "github.com/wneessen/go-mail"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// ErrDisabled is returned by a disabled sender's Send. A caller that reaches
// it has a configuration problem, not a delivery problem.
var ErrDisabled = errors.New("mail is disabled")

// errIncompleteConfig reports that NewSMTPSender was asked to build a sender
// from a Config that Validate would reject.
var errIncompleteConfig = errors.New("mail: cannot build a sender from a disabled or incomplete config")

// errUnknownTLSPolicy reports a TLSPolicy value that passed struct
// validation's oneof but is not one this package knows how to apply. It
// exists only as a defensive fallback: TLSPolicy's validate tag already
// restricts the value to the three cases handled below.
var errUnknownTLSPolicy = errors.New("mail: unknown TLS policy")

// Message is a single outbound plain-text message.
type Message struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// Sender delivers a message. It is an interface with one method so the email
// code path can hold either a real SMTP client or the disabled sender without
// knowing which.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// SMTPSender delivers messages through a configured SMTP server.
type SMTPSender struct {
	client  *gomail.Client
	from    string
	timeout configtype.Duration
	logger  *zap.Logger
}

// NewSMTPSender builds a sender from cfg. It returns an error when cfg is
// disabled or incomplete, so a caller cannot obtain a sender that will fail on
// every message.
func NewSMTPSender(cfg Config, logger *zap.Logger) (*SMTPSender, error) {
	if err := cfg.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("%w: %w", errIncompleteConfig, err)
	}

	if !cfg.Enabled {
		return nil, errIncompleteConfig
	}

	opts := []gomail.Option{
		gomail.WithPort(cfg.Port),
		gomail.WithTimeout(cfg.Timeout.Duration()),
	}

	switch cfg.TLSPolicy {
	case "tls":
		opts = append(opts, gomail.WithSSL())
	case "starttls":
		opts = append(opts, gomail.WithTLSPolicy(gomail.TLSMandatory))
	case "none":
		opts = append(opts, gomail.WithTLSPolicy(gomail.NoTLS))
		logger.Warn("mail TLS policy is none: mail will be sent in the clear")
	default:
		return nil, fmt.Errorf("%w: %q", errUnknownTLSPolicy, cfg.TLSPolicy)
	}

	if cfg.Username != "" {
		opts = append(opts,
			gomail.WithUsername(cfg.Username),
			gomail.WithPassword(cfg.Password.Expose()),
			gomail.WithSMTPAuth(gomail.SMTPAuthAutoDiscover),
		)
	}

	client, err := gomail.NewClient(cfg.Host, opts...)
	if err != nil {
		return nil, fmt.Errorf("mail: building SMTP client: %w", err)
	}

	return &SMTPSender{
		client:  client,
		from:    cfg.From,
		timeout: cfg.Timeout,
		logger:  logger,
	}, nil
}

// Send delivers msg, bounded by ctx and by the configured timeout.
func (s *SMTPSender) Send(ctx context.Context, msg Message) error {
	sendCtx, cancel := context.WithTimeout(ctx, s.timeout.Duration())
	defer cancel()

	message := gomail.NewMsg()

	if err := message.From(s.from); err != nil {
		return fmt.Errorf("mail: setting from address: %w", err)
	}

	if err := message.To(msg.To); err != nil {
		return fmt.Errorf("mail: setting recipient: %w", err)
	}

	message.Subject(msg.Subject)
	message.SetBodyString(gomail.TypeTextPlain, msg.Body)

	// The recipient is deliberately absent from both entries: an address
	// is personal data, and the subject is enough to tell one kind of
	// message from another (AC-008.91).
	if err := s.client.DialAndSendWithContext(sendCtx, message); err != nil {
		s.logger.Error("mail send failed",
			zap.String("subject", msg.Subject),
			zap.Error(err),
		)

		return fmt.Errorf("mail: sending message: %w", err)
	}

	s.logger.Info("mail sent",
		zap.String("subject", msg.Subject),
	)

	return nil
}

// DisabledSender rejects every message with ErrDisabled. It exists so that the
// rest of the service holds a non-nil Sender whether or not mail is
// configured, rather than nil-checking at every call site.
type DisabledSender struct{}

// NewDisabledSender returns a sender that rejects every message.
func NewDisabledSender() *DisabledSender {
	return &DisabledSender{}
}

// Send always returns ErrDisabled without contacting any server.
func (DisabledSender) Send(_ context.Context, _ Message) error {
	return ErrDisabled
}
