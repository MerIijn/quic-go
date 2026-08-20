package http3

import (
	cryptotls "crypto/tls"

	tls "github.com/MerIijn/utls"
)

// toStdConnState converts a uTLS ConnectionState to a crypto/tls ConnectionState
// for the boundaries where http3 hands state to the standard library
// (http.Response.TLS, http.Request.TLS, net/http/httptrace).
func toStdConnState(s tls.ConnectionState) cryptotls.ConnectionState {
	return cryptotls.ConnectionState{
		Version:                     s.Version,
		HandshakeComplete:           s.HandshakeComplete,
		DidResume:                   s.DidResume,
		CipherSuite:                 s.CipherSuite,
		NegotiatedProtocol:          s.NegotiatedProtocol,
		ServerName:                  s.ServerName,
		PeerCertificates:            s.PeerCertificates,
		VerifiedChains:              s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps,
		OCSPResponse:                s.OCSPResponse,
		TLSUnique:                   s.TLSUnique,
	}
}
