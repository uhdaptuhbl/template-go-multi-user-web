package invite

import (
	"fmt"

	"rsc.io/qr"
)

// minScale is the smallest pixel scale QR accepts. rsc.io/qr's Code.PNG
// panics with "invalid flate repeat" at a Scale of 1: its border-row encoder
// computes b.repeat((scale-1)*(1+n), 1+n), which becomes repeat(0, ...) and
// hits that function's n < 3 guard. This pins the pinned dependency's actual
// behavior, which its documentation does not mention, rather than a
// requirement of this package.
const minScale = 2

// maxScale is the largest pixel scale QR accepts. A path parameter cannot ask
// for an enormous image beyond this.
const maxScale = 16

// QR renders url as a PNG QR code at the given pixel scale. It performs no
// lookup and no validation: it is a pure function from a string to an image,
// so the route that serves it is neither an oracle for which invites exist nor
// a way to spend database work without a session.
func QR(url string, scale int) ([]byte, error) {
	clamped := min(max(scale, minScale), maxScale)

	code, err := qr.Encode(url, qr.M)
	if err != nil {
		return nil, fmt.Errorf("invite: encoding qr code: %w", err)
	}

	code.Scale = clamped

	return code.PNG(), nil
}
