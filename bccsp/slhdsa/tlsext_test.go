//go:build tlsext

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package slhdsa_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext/pkixexttest"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/stretchr/testify/require"
)

func TestTLSSchemesRegistered(t *testing.T) {
	var codepoints []uint16
	for _, s := range pkixext.TLSSchemes() {
		codepoints = append(codepoints, s.Codepoint)
	}
	for _, ps := range slhdsa.ParameterSets() {
		require.Contains(t, codepoints, slhdsa.TLSCodepoint(ps), ps.Name)
	}
}

// slhdsaLeaf issues an SLH-DSA leaf for host under pki and loads it with its key.
func slhdsaLeaf(t *testing.T, pki *pkixexttest.TLSPKI, host string, ps slhdsa.ParameterSet) tls.Certificate {
	key, err := slhdsa.GenerateKey(ps)
	require.NoError(t, err)
	cert, err := pki.IssueLeafFor(host, key.Public())
	require.NoError(t, err)
	keyDER, err := slhdsa.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pair, err := pkixext.X509KeyPair(pkixexttest.PEM(cert), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, err)
	return pair
}

// TestTLSHandshakeSLHDSALeaf runs mutual TLS 1.3 with SLH-DSA leaves on both sides, so that both
// CertificateVerify messages are SLH-DSA, and checks that TLS 1.2 cannot negotiate it.
func TestTLSHandshakeSLHDSALeaf(t *testing.T) {
	pki, err := pkixexttest.NewTLSPKI("org1", slhdsa.SHA2_128f)
	require.NoError(t, err)
	anchors := []*x509.Certificate{pki.Root, pki.Intermediate}
	serverCert := slhdsaLeaf(t, pki, "orderer.org1", slhdsa.SHA2_128f)
	clientCert := slhdsaLeaf(t, pki, "peer0.org1", slhdsa.SHA2_128f)

	newServer := func(maxVersion uint16) *tls.Config {
		cfg := &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, MaxVersion: maxVersion}
		pkixext.ConfigureServerVerification(cfg, anchors)
		return cfg
	}
	client := &tls.Config{ServerName: "orderer.org1", Certificates: []tls.Certificate{clientCert}}
	pkixext.ConfigureClientVerification(client, anchors)

	run := func(server *tls.Config) (tls.ConnectionState, error, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()
		done := make(chan error, 1)
		var serverState tls.ConnectionState
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				done <- err
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			srv := tls.Server(conn, server)
			err = srv.Handshake()
			if err == nil {
				_, err = srv.Read(make([]byte, 1))
			}
			serverState = srv.ConnectionState()
			done <- err
		}()
		conn, err := tls.Dial("tcp", ln.Addr().String(), client)
		if err != nil {
			<-done
			return tls.ConnectionState{}, err, nil
		}
		defer conn.Close()
		_, err = conn.Write([]byte{1})
		serverErr := <-done
		if err == nil && serverErr != nil {
			_, err = conn.Read(make([]byte, 1))
		}
		require.NoError(t, err)
		require.IsType(t, &slhdsa.PublicKey{}, serverState.PeerCertificates[0].PublicKey, "the server sees the client SLH-DSA key")
		return conn.ConnectionState(), err, serverErr
	}

	state, clientErr, serverErr := run(newServer(0))
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	require.Equal(t, uint16(tls.VersionTLS13), state.Version)
	require.IsType(t, &slhdsa.PublicKey{}, state.PeerCertificates[0].PublicKey, "the client sees the server SLH-DSA key")

	_, clientErr, _ = run(newServer(tls.VersionTLS12))
	require.Error(t, clientErr, "SLH-DSA must not be negotiated in TLS 1.2")
}
