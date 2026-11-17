//go:build tlsext

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext/pkixexttest"
	"github.com/stretchr/testify/require"
)

var compositeOIDs = []asn1.ObjectIdentifier{
	composite.OIDMLDSA44ECDSAP256SHA256, composite.OIDMLDSA65ECDSAP384SHA512, composite.OIDMLDSA87ECDSAP384SHA512,
	composite.OIDSLHDSASHA2128sECDSAP256SHA256, composite.OIDSLHDSASHA2128fECDSAP256SHA256,
	composite.OIDSLHDSASHA2192sECDSAP384SHA512, composite.OIDSLHDSASHA2192fECDSAP384SHA512,
	composite.OIDSLHDSASHA2256sECDSAP384SHA512, composite.OIDSLHDSASHA2256fECDSAP384SHA512,
}

func TestTLSSchemesRegistered(t *testing.T) {
	registered := map[uint16]string{}
	for _, s := range pkixext.TLSSchemes() {
		registered[s.Codepoint] = s.Name
	}
	for _, oid := range compositeOIDs {
		alg, err := composite.AlgorithmByOID(oid)
		require.NoError(t, err)
		require.Equal(t, composite.TLSName(alg), registered[composite.TLSCodepoint(alg)], alg.Label)
	}
}

// compositeChain creates a composite root of alg and two leaves it issues, for 127.0.0.1 and both
// TLS roles, loaded with their keys.
func compositeChain(t *testing.T, alg composite.Algorithm) (*x509.Certificate, tls.Certificate, tls.Certificate) {
	rootKey, err := composite.GenerateKey(alg)
	require.NoError(t, err)
	rootTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tlsroot"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	root, err := pkixexttest.CreateCertificate(rootTpl, nil, rootKey.Public(), rootKey)
	require.NoError(t, err)
	leaf := func(serial int64, host string) tls.Certificate {
		key, err := composite.GenerateKey(alg)
		require.NoError(t, err)
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: host},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			DNSNames: []string{host}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		cert, err := pkixexttest.CreateCertificate(tpl, root, key.Public(), rootKey)
		require.NoError(t, err)
		keyDER, err := composite.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		pair, err := pkixext.X509KeyPair(pkixexttest.PEM(cert), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
		require.NoError(t, err)
		return pair
	}
	return root, leaf(2, "orderer.org1"), leaf(3, "peer0.org1")
}

// TestTLSHandshakeCompositeLeaf runs mutual TLS 1.3 over a composite chain, so that both
// CertificateVerify messages are composite, for one ML-DSA and one SLH-DSA pair.
func TestTLSHandshakeCompositeLeaf(t *testing.T) {
	for _, oid := range []asn1.ObjectIdentifier{composite.OIDMLDSA44ECDSAP256SHA256, composite.OIDSLHDSASHA2128fECDSAP256SHA256} {
		alg, err := composite.AlgorithmByOID(oid)
		require.NoError(t, err)
		t.Run(alg.Label, func(t *testing.T) {
			root, serverCert, clientCert := compositeChain(t, alg)
			anchors := []*x509.Certificate{root}
			server := &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert}
			pkixext.ConfigureServerVerification(server, anchors)
			client := &tls.Config{ServerName: "orderer.org1", Certificates: []tls.Certificate{clientCert}}
			pkixext.ConfigureClientVerification(client, anchors)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			done := make(chan tls.ConnectionState, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					close(done)
					return
				}
				defer conn.Close()
				srv := tls.Server(conn, server)
				srv.SetDeadline(time.Now().Add(10 * time.Second))
				if srv.Handshake() == nil {
					srv.Read(make([]byte, 1))
				}
				done <- srv.ConnectionState()
			}()
			conn, err := tls.Dial("tcp", ln.Addr().String(), client)
			require.NoError(t, err)
			defer conn.Close()
			_, err = conn.Write([]byte{1})
			require.NoError(t, err)
			serverState := <-done
			require.Equal(t, uint16(tls.VersionTLS13), conn.ConnectionState().Version)
			require.IsType(t, &composite.PublicKey{}, conn.ConnectionState().PeerCertificates[0].PublicKey)
			require.NotEmpty(t, serverState.PeerCertificates)
			require.IsType(t, &composite.PublicKey{}, serverState.PeerCertificates[0].PublicKey)
		})
	}
}
