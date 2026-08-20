package handshake

import tls "github.com/MerIijn/utls"

// uTLS (a crypto/tls fork) does not expose the Go 1.26 QUICErrorEvent, so we use
// a sentinel that never matches a real event; handshake errors surface via the
// Start/HandleData return values instead.
const quicErrorEvent tls.QUICEventKind = -1

func extractQUICEventError(tls.QUICEvent) error { return nil }
