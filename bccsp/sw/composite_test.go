/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	bccspsigner "github.com/hyperledger/fabric-lib-go/bccsp/signer"
	"github.com/stretchr/testify/require"
)

// Vetores oficiais do draft; a origem está em testdata/composite-sigs-19/SOURCE.
const compositeBCCSPVectorsPath = "../composite/testdata/composite-sigs-19/testvectors.json"

type compositeBCCSPVectorFile struct {
	M     string `json:"m"`
	Ctx   string `json:"ctx"`
	Tests []struct {
		TcID         string `json:"tcId"`
		PK           string `json:"pk"`
		SKPKCS8      string `json:"sk_pkcs8"`
		X5c          string `json:"x5c"`
		S            string `json:"s"`
		SWithContext string `json:"sWithContext"`
	} `json:"tests"`
}

// OIDs da seção 7 do draft, escritos como valores literais.
var compositeBCCSPFixtures = []struct {
	tcID string
	oid  asn1.ObjectIdentifier
}{
	{"id-MLDSA44-ECDSA-P256-SHA256", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 40}},
	{"id-MLDSA65-ECDSA-P384-SHA512", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 46}},
	{"id-MLDSA87-ECDSA-P384-SHA512", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 49}},
}

type compositeBCCSPVector struct {
	pk, skPKCS8, s, sWithContext []byte
	cert                         *x509.Certificate
}

func loadCompositeBCCSPVectors(t *testing.T) (m, ctx []byte, byID map[string]compositeBCCSPVector) {
	t.Helper()
	raw, err := os.ReadFile(compositeBCCSPVectorsPath)
	require.NoError(t, err)
	var file compositeBCCSPVectorFile
	require.NoError(t, json.Unmarshal(raw, &file))

	decode := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		require.NoError(t, err)
		return b
	}
	byID = map[string]compositeBCCSPVector{}
	for _, tc := range file.Tests {
		cert, err := x509.ParseCertificate(decode(tc.X5c))
		require.NoError(t, err)
		byID[tc.TcID] = compositeBCCSPVector{
			pk: decode(tc.PK), skPKCS8: decode(tc.SKPKCS8),
			s: decode(tc.S), sWithContext: decode(tc.SWithContext), cert: cert,
		}
	}
	return decode(file.M), decode(file.Ctx), byID
}

func newCompositeTestCSP(t *testing.T, dir string) bccsp.BCCSP {
	t.Helper()
	ks, err := NewFileBasedKeyStore(nil, dir, false)
	require.NoError(t, err)
	csp, err := NewDefaultSecurityLevelWithKeystore(ks)
	require.NoError(t, err)
	return csp
}

func TestCompositeBCCSPKeyGen(t *testing.T) {
	csp := newCompositeTestCSP(t, t.TempDir())
	msg := []byte("mensagem")
	for _, fx := range compositeBCCSPFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			k, err := csp.KeyGen(&bccsp.CompositeKeyGenOpts{OID: fx.oid, Temporary: true})
			require.NoError(t, err)
			require.True(t, k.Private())
			require.False(t, k.Symmetric())

			pub, err := k.PublicKey()
			require.NoError(t, err)
			require.Equal(t, k.SKI(), pub.SKI())

			spki, err := pub.Bytes()
			require.NoError(t, err)
			parsed, err := composite.ParsePKIXPublicKey(spki)
			require.NoError(t, err)
			require.Equal(t, fx.oid.String(), parsed.Algorithm.OID.String())

			sig, err := csp.Sign(k, msg, nil)
			require.NoError(t, err)
			valid, err := csp.Verify(pub, sig, msg, nil)
			require.NoError(t, err)
			require.True(t, valid)
			valid, err = csp.Verify(k, sig, msg, nil)
			require.NoError(t, err)
			require.True(t, valid)
		})
	}

	_, err := csp.KeyGen(&bccsp.CompositeKeyGenOpts{OID: asn1.ObjectIdentifier{1, 2, 3}, Temporary: true})
	require.Error(t, err)
}

func TestCompositeBCCSPImportAgainstVectors(t *testing.T) {
	m, ctx, vectors := loadCompositeBCCSPVectors(t)
	csp := newCompositeTestCSP(t, t.TempDir())
	for _, fx := range compositeBCCSPFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			v := vectors[fx.tcID]

			priv, err := csp.KeyImport(v.skPKCS8, &bccsp.CompositePrivateKeyImportOpts{Temporary: true})
			require.NoError(t, err)

			fromCert, err := csp.KeyImport(v.cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
			require.NoError(t, err)
			require.Equal(t, priv.SKI(), fromCert.SKI())
			spki, err := fromCert.Bytes()
			require.NoError(t, err)
			require.Equal(t, v.cert.RawSubjectPublicKeyInfo, spki)

			fromPKIX, err := csp.KeyImport(spki, &bccsp.CompositePKIXPublicKeyImportOpts{Temporary: true})
			require.NoError(t, err)
			require.Equal(t, priv.SKI(), fromPKIX.SKI())

			goPub, err := composite.ParsePKIXPublicKey(spki)
			require.NoError(t, err)
			fromGo, err := csp.KeyImport(goPub, &bccsp.CompositeGoPublicKeyImportOpts{Temporary: true})
			require.NoError(t, err)
			require.Equal(t, priv.SKI(), fromGo.SKI())

			valid, err := csp.Verify(fromCert, v.s, m, nil)
			require.NoError(t, err)
			require.True(t, valid)
			valid, err = csp.Verify(fromCert, v.sWithContext, m, &composite.SignerOpts{Context: ctx})
			require.NoError(t, err)
			require.True(t, valid)
			valid, err = csp.Verify(fromCert, v.sWithContext, m, nil)
			require.NoError(t, err)
			require.False(t, valid)

			sig, err := csp.Sign(priv, m, &composite.SignerOpts{Context: ctx})
			require.NoError(t, err)
			valid, err = csp.Verify(fromCert, sig, m, &composite.SignerOpts{Context: ctx})
			require.NoError(t, err)
			require.True(t, valid)
		})
	}
}

func TestCompositeBCCSPRejectsDigestOpts(t *testing.T) {
	m, _, vectors := loadCompositeBCCSPVectors(t)
	csp := newCompositeTestCSP(t, t.TempDir())
	v := vectors[compositeBCCSPFixtures[0].tcID]
	priv, err := csp.KeyImport(v.skPKCS8, &bccsp.CompositePrivateKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	pub, err := csp.KeyImport(v.cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)

	_, err = csp.Sign(priv, m, crypto.SHA256)
	require.Error(t, err)
	_, err = csp.Verify(pub, v.s, m, crypto.SHA256)
	require.Error(t, err)

	valid, err := csp.Verify(pub, v.s, m, crypto.Hash(0))
	require.NoError(t, err)
	require.True(t, valid)
}

func TestCompositeBCCSPKeystore(t *testing.T) {
	m, _, vectors := loadCompositeBCCSPVectors(t)
	for _, fx := range compositeBCCSPFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			v := vectors[fx.tcID]
			dir := t.TempDir()
			csp := newCompositeTestCSP(t, dir)

			priv, err := csp.KeyImport(v.skPKCS8, &bccsp.CompositePrivateKeyImportOpts{Temporary: false})
			require.NoError(t, err)
			ski := hex.EncodeToString(priv.SKI())

			stored, err := os.ReadFile(filepath.Join(dir, ski+"_sk"))
			require.NoError(t, err)
			block, _ := pem.Decode(stored)
			require.NotNil(t, block)
			require.Equal(t, "PRIVATE KEY", block.Type)
			require.Equal(t, v.skPKCS8, block.Bytes)

			other := newCompositeTestCSP(t, dir)
			fromCert, err := other.KeyImport(v.cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
			require.NoError(t, err)
			loaded, err := other.GetKey(fromCert.SKI())
			require.NoError(t, err)
			require.True(t, loaded.Private())
			sig, err := other.Sign(loaded, m, nil)
			require.NoError(t, err)
			valid, err := other.Verify(fromCert, sig, m, nil)
			require.NoError(t, err)
			require.True(t, valid)

			require.NoError(t, os.Rename(filepath.Join(dir, ski+"_sk"), filepath.Join(dir, "renamed")))
			searched, err := newCompositeTestCSP(t, dir).GetKey(priv.SKI())
			require.NoError(t, err)
			require.Equal(t, priv.SKI(), searched.SKI())

			_, err = csp.KeyImport(v.cert, &bccsp.X509PublicKeyImportOpts{Temporary: false})
			require.NoError(t, err)
			pubLoaded, err := newCompositeTestCSP(t, dir).GetKey(fromCert.SKI())
			require.NoError(t, err)
			require.NotNil(t, pubLoaded)
		})
	}
}

func TestCompositeBCCSPSigner(t *testing.T) {
	m, ctx, vectors := loadCompositeBCCSPVectors(t)
	csp := newCompositeTestCSP(t, t.TempDir())
	for _, fx := range compositeBCCSPFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			v := vectors[fx.tcID]
			priv, err := csp.KeyImport(v.skPKCS8, &bccsp.CompositePrivateKeyImportOpts{Temporary: true})
			require.NoError(t, err)

			signer, err := bccspsigner.New(csp, priv)
			require.NoError(t, err)
			pub, ok := signer.Public().(*composite.PublicKey)
			require.True(t, ok)
			raw, err := pub.Bytes()
			require.NoError(t, err)
			require.Equal(t, v.pk, raw)

			sig, err := signer.Sign(rand.Reader, m, &composite.SignerOpts{Context: ctx})
			require.NoError(t, err)
			require.NoError(t, composite.Verify(pub, m, sig, ctx))
		})
	}
}

func TestCompositeBCCSPRejectsOtherKeys(t *testing.T) {
	csp := newCompositeTestCSP(t, t.TempDir())
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	_, err = csp.KeyImport(pkcs8, &bccsp.CompositePrivateKeyImportOpts{Temporary: true})
	require.Error(t, err)

	spki, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)
	_, err = csp.KeyImport(spki, &bccsp.CompositePKIXPublicKeyImportOpts{Temporary: true})
	require.Error(t, err)

	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ecdsa"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &ecKey.PublicKey, ecKey)
	require.NoError(t, err)
	ecCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	imported, err := csp.KeyImport(ecCert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	require.IsType(t, &ecdsaPublicKey{}, imported)

	truncated, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: compositeBCCSPFixtures[0].oid},
		PublicKey: asn1.BitString{Bytes: make([]byte, 10), BitLength: 80},
	})
	require.NoError(t, err)
	_, err = csp.KeyImport(&x509.Certificate{RawSubjectPublicKeyInfo: truncated}, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	require.Error(t, err)
}
