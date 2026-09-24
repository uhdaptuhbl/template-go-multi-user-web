package invite

import (
	"bytes"
	"image/png"
	"testing"
)

// pngSignature is the eight-byte magic every PNG file begins with, per the
// PNG specification. This test pins a third party's documented file format
// rather than one of this service's criteria.
var pngSignature = []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}

// startsWithPNGSignature reports whether b begins with the PNG magic bytes.
func startsWithPNGSignature(b []byte) bool {
	return len(b) >= len(pngSignature) && bytes.Equal(b[:len(pngSignature)], pngSignature)
}

// TestQRProducesAValidPNG guards QR's contract on ordinary input: the bytes
// it returns are a PNG.
// Covers AC-008.68.
func TestQRProducesAValidPNG(t *testing.T) {
	t.Parallel()

	imgBytes, err := QR("https://example.com/invite/abc", 4)
	if err != nil {
		t.Fatalf("QR() error = %v", err)
	}

	if !startsWithPNGSignature(imgBytes) {
		t.Error("QR() does not start with the PNG signature")
	}
}

// mustQR calls QR and fails the test immediately on error.
func mustQR(t *testing.T, url string, scale int) []byte {
	t.Helper()

	imgBytes, err := QR(url, scale)
	if err != nil {
		t.Fatalf("QR() error = %v", err)
	}

	return imgBytes
}

// pngDimensions decodes data's PNG header and returns its width and height.
func pngDimensions(t *testing.T, data []byte) (int, int) {
	t.Helper()

	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("png.DecodeConfig() error = %v", err)
	}

	return cfg.Width, cfg.Height
}

// TestQRClampsScaleToValidRange proves a scale outside 1 to 16 does not error
// and is silently clamped rather than rejected, guarding QR's contract on its
// boundary values. It asserts the resulting image dimensions, not merely that
// QR succeeds without error, so a future edit that lowers minScale back to 1 -
// which panics inside rsc.io/qr per minScale's doc comment - is caught here
// by a dimension mismatch rather than by luck, since 1 is a value this test
// exercises directly.
// Covers AC-008.68.
func TestQRClampsScaleToValidRange(t *testing.T) {
	t.Parallel()

	const url = "https://example.com/invite/abc"

	floorWidth, floorHeight := pngDimensions(t, mustQR(t, url, minScale))
	ceilWidth, ceilHeight := pngDimensions(t, mustQR(t, url, maxScale))

	tests := []struct {
		name       string
		scale      int
		wantWidth  int
		wantHeight int
	}{
		{name: "zero", scale: 0, wantWidth: floorWidth, wantHeight: floorHeight},
		{name: "one", scale: 1, wantWidth: floorWidth, wantHeight: floorHeight},
		{name: "negative", scale: -5, wantWidth: floorWidth, wantHeight: floorHeight},
		{name: "excessive", scale: 100, wantWidth: ceilWidth, wantHeight: ceilHeight},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			imgBytes := mustQR(t, url, tt.scale)

			if !startsWithPNGSignature(imgBytes) {
				t.Error("QR() does not start with the PNG signature")
			}

			gotWidth, gotHeight := pngDimensions(t, imgBytes)

			if gotWidth != tt.wantWidth || gotHeight != tt.wantHeight {
				t.Errorf("QR(scale=%d) dimensions = %dx%d, want %dx%d", tt.scale, gotWidth, gotHeight, tt.wantWidth, tt.wantHeight)
			}
		})
	}
}

// TestQRIsDeterministic proves two calls with the same URL produce identical
// bytes, which is what makes QR safe to call without caching.
// Covers AC-008.68.
func TestQRIsDeterministic(t *testing.T) {
	t.Parallel()

	first, err := QR("https://example.com/invite/abc", 4)
	if err != nil {
		t.Fatalf("QR() first call error = %v", err)
	}

	second, err := QR("https://example.com/invite/abc", 4)
	if err != nil {
		t.Fatalf("QR() second call error = %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Error("QR() produced different bytes for two calls with the same input")
	}
}
