package mail

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// recipientAddress is the address every test in this file mails, chosen to be
// unmistakable if it turns up in a log entry.
const recipientAddress = "private-recipient@example.com"

// loopbackConfig returns a Config that sends in the clear to port on the
// loopback interface, with a timeout short enough that a hung exchange fails
// the test by name rather than waiting out the package timeout.
func loopbackConfig(port int) Config {
	cfg := completeConfig()
	cfg.Host = "127.0.0.1"
	cfg.Port = port
	cfg.TLSPolicy = "none"
	cfg.Timeout = configtype.Duration(5 * time.Second)

	return cfg
}

// listenLoopback listens on an ephemeral loopback port and returns the
// listener with its port.
func listenLoopback(t *testing.T) (net.Listener, int) {
	t.Helper()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %v is not a TCP address", listener.Addr())
	}

	return listener, addr.Port
}

// closedLoopbackPort returns a loopback port nothing is listening on, so a
// connection to it is refused.
func closedLoopbackPort(t *testing.T) int {
	t.Helper()

	listener, port := listenLoopback(t)

	if closeErr := listener.Close(); closeErr != nil {
		t.Fatalf("closing ephemeral listener: %v", closeErr)
	}

	return port
}

// acceptingSMTPServer starts a minimal SMTP server on loopback that accepts
// one message and returns its port. Cleanup closes the listener and waits for
// the session to end, failing the test if the server's own connection could
// not be closed.
func acceptingSMTPServer(t *testing.T) int {
	t.Helper()

	listener, port := listenLoopback(t)
	done := make(chan error, 1)

	go func() {
		done <- serveOneSMTPSession(listener)
	}()

	t.Cleanup(func() {
		closeErr := listener.Close()
		sessionErr := <-done

		if err := errors.Join(closeErr, sessionErr); err != nil {
			t.Errorf("fake SMTP server: %v", err)
		}
	})

	return port
}

// serveOneSMTPSession accepts a single connection on listener and plays the
// server side of one message's exchange, answering every command with
// success, which is all a client sending in the clear without authentication
// needs. It returns when the client quits, the connection fails, or the
// deadline passes. It reports a connection that never arrived or could not be
// closed; an exchange that goes wrong already fails the test through the
// client.
func serveOneSMTPSession(listener net.Listener) error {
	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("accepting the client's connection: %w", err)
	}

	if deadlineErr := conn.SetDeadline(time.Now().Add(10 * time.Second)); deadlineErr == nil {
		playSMTPServer(conn)
	}

	if closeErr := conn.Close(); closeErr != nil {
		return fmt.Errorf("closing connection: %w", closeErr)
	}

	return nil
}

// playSMTPServer answers the commands read from conn until the client quits
// or the connection fails.
func playSMTPServer(conn net.Conn) {
	reader := bufio.NewReader(conn)

	reply := func(line string) bool {
		_, writeErr := fmt.Fprintf(conn, "%s\r\n", line)

		return writeErr == nil
	}

	if !reply("220 localhost ESMTP") {
		return
	}

	inData := false

	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			return
		}

		line = strings.TrimRight(line, "\r\n")

		if inData {
			if line == "." {
				inData = false

				if !reply("250 OK") {
					return
				}
			}

			continue
		}

		command := strings.ToUpper(strings.SplitN(line, " ", 2)[0])

		switch command {
		case "EHLO", "HELO":
			if !reply("250 localhost") {
				return
			}
		case "DATA":
			inData = true

			if !reply("354 end with .") {
				return
			}
		case "QUIT":
			reply("221 bye")

			return
		default:
			if !reply("250 OK") {
				return
			}
		}
	}
}

// assertNoEntryNamesTheRecipient fails the test if any logged message or
// field value contains the recipient's address.
func assertNoEntryNamesTheRecipient(t *testing.T, logs *observer.ObservedLogs) {
	t.Helper()

	for _, entry := range logs.All() {
		if strings.Contains(entry.Message, recipientAddress) {
			t.Errorf("log message %q contains the recipient address", entry.Message)
		}

		for key, value := range entry.ContextMap() {
			if strings.Contains(fmt.Sprint(value), recipientAddress) {
				t.Errorf("log entry %q field %q = %v, contains the recipient address", entry.Message, key, value)
			}
		}
	}
}

// TestSendDoesNotLogTheRecipientOnFailure covers AC-008.91 for a send the
// server refuses, and checks the failure entry carries the cause.
func TestSendDoesNotLogTheRecipientOnFailure(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zap.DebugLevel)

	sender, err := NewSMTPSender(loopbackConfig(closedLoopbackPort(t)), zap.New(core))
	if err != nil {
		t.Fatalf("NewSMTPSender() error = %v", err)
	}

	sendErr := sender.Send(t.Context(), Message{To: recipientAddress, Subject: "subject", Body: "body"})
	if sendErr == nil {
		t.Fatal("Send() error = nil, want a connection failure")
	}

	failures := logs.FilterMessage("mail send failed").All()
	if len(failures) != 1 {
		t.Fatalf("got %d %q entries, want 1", len(failures), "mail send failed")
	}

	if _, ok := failures[0].ContextMap()["error"]; !ok {
		t.Errorf("failure entry fields = %v, want an error field", failures[0].ContextMap())
	}

	assertNoEntryNamesTheRecipient(t, logs)
}

// TestSendDoesNotLogTheRecipientOnSuccess covers AC-008.91 for a message the
// server accepts.
func TestSendDoesNotLogTheRecipientOnSuccess(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zap.DebugLevel)

	sender, err := NewSMTPSender(loopbackConfig(acceptingSMTPServer(t)), zap.New(core))
	if err != nil {
		t.Fatalf("NewSMTPSender() error = %v", err)
	}

	if sendErr := sender.Send(t.Context(), Message{To: recipientAddress, Subject: "subject", Body: "body"}); sendErr != nil {
		t.Fatalf("Send() error = %v, want nil", sendErr)
	}

	if got := logs.FilterMessage("mail sent").Len(); got != 1 {
		t.Fatalf("got %d %q entries, want 1", got, "mail sent")
	}

	assertNoEntryNamesTheRecipient(t, logs)
}
