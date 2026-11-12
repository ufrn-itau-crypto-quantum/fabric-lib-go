/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pkixext_test

import (
	"crypto"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/stretchr/testify/require"
)

type tlsPKI struct {
	root, inter *x509.Certificate
	interKey    crypto.Signer
}

// newTLSPKI builds an SLH-DSA root and intermediate, as the TLS CA of an organization.
func newTLSPKI(t *testing.T, name string) tlsPKI {
	t.Helper()
	rootKey := slhdsaKey(t, slhdsa.SHA2_128f)
	root := issueCert(t, caTemplate(name+"-tlsroot"), nil, rootKey.Public(), rootKey)
	interKey := slhdsaKey(t, slhdsa.SHA2_128f)
	inter := issueCert(t, caTemplate(name+"-tlsinter"), root, interKey.Public(), rootKey)
	return tlsPKI{root: root, inter: inter, interKey: interKey}
}

// issueLeaf issues an ML-DSA-44 TLS certificate for host, valid for both roles unless usages says
// otherwise.
func (p tlsPKI) issueLeaf(t *testing.T, host string, usages ...x509.ExtKeyUsage) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	tpl := leafTemplate(host)
	tpl.DNSNames = []string{host}
	tpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if len(usages) > 0 {
		tpl.ExtKeyUsage = usages
	}
	leaf := issueCert(t, tpl, p.inter, key.Public(), p.interKey)
	return leaf, tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
}

func TestVerifyTLSPeer(t *testing.T) {
	pki := newTLSPKI(t, "org1")
	other := newTLSPKI(t, "org2")
	leaf, _ := pki.issueLeaf(t, "peer0.org1")
	clientOnly, _ := pki.issueLeaf(t, "client.org1", x509.ExtKeyUsageClientAuth)
	anchors := []*x509.Certificate{pki.root, pki.inter}
	serverOpts := func(name string) pkixext.TLSVerifyOptions {
		return pkixext.TLSVerifyOptions{Roots: anchors, DNSName: name, KeyUsage: x509.ExtKeyUsageServerAuth}
	}

	t.Run("leaf only, intermediate among the anchors", func(t *testing.T) {
		chains, err := pkixext.VerifyTLSPeer([][]byte{leaf.Raw}, serverOpts("peer0.org1"))
		require.NoError(t, err)
		require.NotEmpty(t, chains)
		require.True(t, chains[0][0].Equal(leaf))
	})
	t.Run("intermediate sent by the peer", func(t *testing.T) {
		opts := serverOpts("peer0.org1")
		opts.Roots = []*x509.Certificate{pki.root}
		chains, err := pkixext.VerifyTLSPeer([][]byte{leaf.Raw, pki.inter.Raw}, opts)
		require.NoError(t, err)
		require.Len(t, chains[0], 3)
	})
	t.Run("no hostname check without DNSName", func(t *testing.T) {
		_, err := pkixext.VerifyTLSPeer([][]byte{leaf.Raw}, serverOpts(""))
		require.NoError(t, err)
	})

	rejected := map[string]struct {
		raw  [][]byte
		opts func() pkixext.TLSVerifyOptions
		msg  string
	}{
		"no certificate": {nil, func() pkixext.TLSVerifyOptions { return serverOpts("peer0.org1") }, "no certificate"},
		"root of another PKI": {[][]byte{leaf.Raw}, func() pkixext.TLSVerifyOptions {
			o := serverOpts("peer0.org1")
			o.Roots = []*x509.Certificate{other.root, other.inter}
			return o
		}, "unknown authority"},
		"no path to the root": {[][]byte{leaf.Raw}, func() pkixext.TLSVerifyOptions {
			o := serverOpts("peer0.org1")
			o.Roots = []*x509.Certificate{pki.root}
			return o
		}, "unknown authority"},
		"expired": {[][]byte{leaf.Raw}, func() pkixext.TLSVerifyOptions {
			o := serverOpts("peer0.org1")
			o.CurrentTime = time.Now().Add(2 * time.Hour)
			return o
		}, "expired"},
		"client certificate used as server": {[][]byte{clientOnly.Raw}, func() pkixext.TLSVerifyOptions {
			return serverOpts("client.org1")
		}, "key usage"},
		"hostname mismatch": {[][]byte{leaf.Raw}, func() pkixext.TLSVerifyOptions { return serverOpts("peer1.org1") }, "peer1.org1"},
		"malformed": {[][]byte{[]byte("junk")}, func() pkixext.TLSVerifyOptions { return serverOpts("peer0.org1") }, "parse"},
	}
	for name, tc := range rejected {
		t.Run(name, func(t *testing.T) {
			_, err := pkixext.VerifyTLSPeer(tc.raw, tc.opts())
			require.ErrorContains(t, err, tc.msg)
		})
	}
}

func TestHasExternal(t *testing.T) {
	ec := ecdsaKey(t)
	ecRoot := issueCert(t, caTemplate("ec"), nil, ec.Public(), ec)
	ml, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	mlRoot := issueCert(t, caTemplate("ml"), nil, ml.Public(), ml)
	pki := newTLSPKI(t, "org1")

	require.False(t, pkixext.HasExternal(nil))
	require.False(t, pkixext.HasExternal([]*x509.Certificate{ecRoot, mlRoot}))
	require.True(t, pkixext.HasExternal([]*x509.Certificate{ecRoot, pki.root}))
	ecUnderSLH := issueCert(t, caTemplate("ec-under-slh"), pki.root, ec.Public(), pki.interKey)
	require.True(t, pkixext.HasExternal([]*x509.Certificate{ecUnderSLH}))
}

func pemCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func TestParseCertificatesPEM(t *testing.T) {
	pki := newTLSPKI(t, "org1")
	bundle := append(pemCert(pki.root), []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")...)
	certs, err := pkixext.ParseCertificatesPEM(bundle, pemCert(pki.inter))
	require.NoError(t, err)
	require.Len(t, certs, 2)
	require.True(t, certs[1].Equal(pki.inter))
}

// handshake runs a TLS handshake over loopback TCP, has the client send one byte and the server
// read it, and returns the error of each side. Reading after the handshake surfaces a client
// certificate rejected by the server, which TLS 1.3 reports to the client only then.
func handshake(t *testing.T, client, server *tls.Config) (clientErr, serverErr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	done := make(chan error, 1)
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
		done <- err
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	cli := tls.Client(conn, client)
	clientErr = cli.Handshake()
	if clientErr == nil {
		_, clientErr = cli.Write([]byte{1})
	}
	serverErr = <-done
	if clientErr == nil && serverErr != nil {
		_, clientErr = cli.Read(make([]byte, 1))
	}
	return clientErr, serverErr
}

func TestConfigureVerificationHandshake(t *testing.T) {
	pki := newTLSPKI(t, "org1")
	other := newTLSPKI(t, "org2")
	anchors := []*x509.Certificate{pki.root, pki.inter}
	_, serverCert := pki.issueLeaf(t, "orderer.org1")
	_, clientCert := pki.issueLeaf(t, "peer0.org1")
	_, strangerCert := other.issueLeaf(t, "peer0.org2")

	newServer := func(clientAuth tls.ClientAuthType, seen *[][]*x509.Certificate) *tls.Config {
		cfg := &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   clientAuth,
			VerifyPeerCertificate: func(_ [][]byte, chains [][]*x509.Certificate) error {
				if seen != nil {
					*seen = chains
				}
				return nil
			},
		}
		pkixext.ConfigureServerVerification(cfg, anchors)
		return cfg
	}
	newClient := func(serverName string, certs ...tls.Certificate) *tls.Config {
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, Certificates: certs}
		pkixext.ConfigureClientVerification(cfg, anchors)
		return cfg
	}

	t.Run("mutual TLS", func(t *testing.T) {
		var seen [][]*x509.Certificate
		server := newServer(tls.RequireAndVerifyClientCert, &seen)
		require.Equal(t, tls.RequireAnyClientCert, server.ClientAuth)
		cErr, sErr := handshake(t, newClient("orderer.org1", clientCert).Clone(), server)
		require.NoError(t, cErr)
		require.NoError(t, sErr)
		require.Len(t, seen, 1)
		require.True(t, seen[0][len(seen[0])-1].Equal(pki.inter))
	})
	t.Run("server name mismatch", func(t *testing.T) {
		cErr, _ := handshake(t, newClient("orderer.org2", clientCert), newServer(tls.RequireAndVerifyClientCert, nil))
		require.ErrorContains(t, cErr, "orderer.org2")
	})
	t.Run("server of another PKI", func(t *testing.T) {
		client := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "orderer.org1", Certificates: []tls.Certificate{clientCert}}
		pkixext.ConfigureClientVerification(client, []*x509.Certificate{other.root, other.inter})
		cErr, _ := handshake(t, client, newServer(tls.RequireAndVerifyClientCert, nil))
		require.ErrorContains(t, cErr, "unknown authority")
	})
	t.Run("client without certificate", func(t *testing.T) {
		_, sErr := handshake(t, newClient("orderer.org1"), newServer(tls.RequireAndVerifyClientCert, nil))
		require.Error(t, sErr)
	})
	t.Run("client of another PKI", func(t *testing.T) {
		_, sErr := handshake(t, newClient("orderer.org1", strangerCert), newServer(tls.RequireAndVerifyClientCert, nil))
		require.ErrorContains(t, sErr, "unknown authority")
	})
	t.Run("optional client certificate", func(t *testing.T) {
		server := newServer(tls.VerifyClientCertIfGiven, nil)
		require.Equal(t, tls.RequestClientCert, server.ClientAuth)
		cErr, sErr := handshake(t, newClient("orderer.org1"), server)
		require.NoError(t, cErr)
		require.NoError(t, sErr)
		_, sErr = handshake(t, newClient("orderer.org1", strangerCert), newServer(tls.VerifyClientCertIfGiven, nil))
		require.ErrorContains(t, sErr, "unknown authority")
	})
	t.Run("server name from the dialed address", func(t *testing.T) {
		base := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{clientCert}}
		cErr, sErr := handshake(t, pkixext.ClientConfigFor(base, anchors, "127.0.0.1:7053"), newServer(tls.RequireAndVerifyClientCert, nil))
		require.NoError(t, cErr)
		require.NoError(t, sErr)
		require.Empty(t, base.ServerName)
		cErr, _ = handshake(t, pkixext.ClientConfigFor(base, anchors, "10.0.0.9:7053"), newServer(tls.RequireAndVerifyClientCert, nil))
		require.ErrorContains(t, cErr, "10.0.0.9")
		cErr, _ = handshake(t, pkixext.ClientConfigFor(base, anchors, "orderer.org1"), newServer(tls.RequireAndVerifyClientCert, nil))
		require.NoError(t, cErr)
	})
	t.Run("modes without verification are kept", func(t *testing.T) {
		cfg := &tls.Config{ClientAuth: tls.RequestClientCert}
		pkixext.ConfigureServerVerification(cfg, anchors)
		require.Equal(t, tls.RequestClientCert, cfg.ClientAuth)
		require.Nil(t, cfg.VerifyPeerCertificate)
	})
}
