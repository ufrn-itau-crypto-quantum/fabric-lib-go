/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pkixexttest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext/pkixexttest"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/stretchr/testify/require"
)

func template(name string, ca bool) *x509.Certificate {
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		SubjectKeyId: []byte(name), BasicConstraintsValid: true, IsCA: ca,
	}
	if ca {
		tpl.KeyUsage = x509.KeyUsageCertSign
	}
	return tpl
}

func TestCreateCertificate(t *testing.T) {
	rootKey, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	require.NoError(t, err)
	root, err := pkixexttest.CreateCertificate(template("root", true), nil, rootKey.Public(), rootKey)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	inter, err := pkixexttest.CreateCertificate(template("inter", true), root, ecKey.Public(), rootKey)
	require.NoError(t, err)
	leafKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	leaf, err := pkixexttest.CreateCertificate(template("leaf", false), inter, leafKey.Public(), ecKey)
	require.NoError(t, err)

	require.Equal(t, x509.MLDSA, leaf.PublicKeyAlgorithm)
	require.True(t, pkixext.IsExternalPublicKey(root.RawSubjectPublicKeyInfo))
	_, err = pkixext.VerifyChain(leaf, pkixext.VerifyOptions{
		Roots: []*x509.Certificate{root}, Intermediates: []*x509.Certificate{inter},
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	require.NoError(t, err)
}

func TestTLSPKI(t *testing.T) {
	p, err := pkixexttest.NewTLSPKI("org1", slhdsa.SHA2_128f)
	require.NoError(t, err)
	certPEM, keyPEM, err := p.IssueLeaf("peer0.org1")
	require.NoError(t, err)
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	anchors, err := pkixext.ParseCertificatesPEM(p.AnchorsPEM())
	require.NoError(t, err)
	block, _ := pem.Decode(certPEM)
	_, err = pkixext.VerifyTLSPeer([][]byte{block.Bytes}, pkixext.TLSVerifyOptions{
		Roots: anchors, DNSName: "127.0.0.1", KeyUsage: x509.ExtKeyUsageClientAuth,
	})
	require.NoError(t, err)
}
