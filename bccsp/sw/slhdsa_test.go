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
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	bccspsigner "github.com/hyperledger/fabric-lib-go/bccsp/signer"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/stretchr/testify/require"
)

// RFC 9909, Appendix C; the origin is in testdata/rfc9909/SOURCE.
const (
	slhdsaRFC9909PrivateKeyPath  = "../slhdsa/testdata/rfc9909/private-key.pem"
	slhdsaRFC9909CertificatePath = "../slhdsa/testdata/rfc9909/certificate.pem"
)

func readSLHDSAPEM(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	require.NotNil(t, block)
	return block.Bytes
}

func loadSLHDSAVectors(t *testing.T) (pkcs8 []byte, cert *x509.Certificate) {
	t.Helper()
	cert, err := x509.ParseCertificate(readSLHDSAPEM(t, slhdsaRFC9909CertificatePath))
	require.NoError(t, err)
	return readSLHDSAPEM(t, slhdsaRFC9909PrivateKeyPath), cert
}

func TestSLHDSABCCSPKeyGen(t *testing.T) {
	msg := []byte("message")
	for _, ps := range slhdsa.ParameterSets() {
		t.Run(ps.Name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			csp := newCompositeTestCSP(t, dir)

			k, err := csp.KeyGen(&bccsp.SLHDSAKeyGenOpts{OID: ps.OID, Temporary: false})
			require.NoError(t, err)
			require.True(t, k.Private())
			require.False(t, k.Symmetric())
			_, err = k.Bytes()
			require.Error(t, err)

			pub, err := k.PublicKey()
			require.NoError(t, err)
			require.Equal(t, k.SKI(), pub.SKI())

			spki, err := pub.Bytes()
			require.NoError(t, err)
			parsed, err := slhdsa.ParsePKIXPublicKey(spki)
			require.NoError(t, err)
			require.Equal(t, ps, parsed.ParameterSet)

			loaded, err := newCompositeTestCSP(t, dir).GetKey(k.SKI())
			require.NoError(t, err)
			require.True(t, loaded.Private())

			sig, err := csp.Sign(loaded, msg, nil)
			require.NoError(t, err)
			require.Len(t, sig, ps.SignatureSize())
			valid, err := csp.Verify(pub, sig, msg, nil)
			require.NoError(t, err)
			require.True(t, valid)
			valid, err = csp.Verify(k, sig, msg, nil)
			require.NoError(t, err)
			require.True(t, valid)
			valid, err = csp.Verify(pub, sig, []byte("other"), nil)
			require.NoError(t, err)
			require.False(t, valid)
		})
	}
}

func TestSLHDSABCCSPKeyGenRejectsOtherOIDs(t *testing.T) {
	csp := newCompositeTestCSP(t, t.TempDir())
	hashSLHDSA := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 35}
	_, err := csp.KeyGen(&bccsp.SLHDSAKeyGenOpts{OID: hashSLHDSA, Temporary: true})
	require.Error(t, err)
	_, err = csp.KeyGen(&bccsp.SLHDSAKeyGenOpts{Temporary: true})
	require.Error(t, err)
}

func TestSLHDSABCCSPImportAgainstRFC9909(t *testing.T) {
	pkcs8, cert := loadSLHDSAVectors(t)
	csp := newCompositeTestCSP(t, t.TempDir())

	priv, err := csp.KeyImport(pkcs8, &bccsp.SLHDSAPrivateKeyImportOpts{Temporary: true})
	require.NoError(t, err)

	fromCert, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	require.IsType(t, &slhdsaPublicKey{}, fromCert)
	require.Equal(t, priv.SKI(), fromCert.SKI())
	spki, err := fromCert.Bytes()
	require.NoError(t, err)
	require.Equal(t, cert.RawSubjectPublicKeyInfo, spki)

	fromPKIX, err := csp.KeyImport(spki, &bccsp.SLHDSAPKIXPublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	require.Equal(t, priv.SKI(), fromPKIX.SKI())

	goPub, err := slhdsa.ParsePKIXPublicKey(spki)
	require.NoError(t, err)
	fromGo, err := csp.KeyImport(goPub, &bccsp.SLHDSAGoPublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	require.Equal(t, priv.SKI(), fromGo.SKI())

	valid, err := csp.Verify(fromCert, cert.Signature, cert.RawTBSCertificate, nil)
	require.NoError(t, err)
	require.True(t, valid)

	sig, err := csp.Sign(priv, cert.RawTBSCertificate, nil)
	require.NoError(t, err)
	valid, err = csp.Verify(fromCert, sig, cert.RawTBSCertificate, nil)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestSLHDSABCCSPHashOptsMeanPure(t *testing.T) {
	pkcs8, cert := loadSLHDSAVectors(t)
	csp := newCompositeTestCSP(t, t.TempDir())
	priv, err := csp.KeyImport(pkcs8, &bccsp.SLHDSAPrivateKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	pub, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	msg := []byte("message")

	for _, opts := range []bccsp.SignerOpts{crypto.SHA256, crypto.SHA384, crypto.Hash(0)} {
		sig, err := csp.Sign(priv, msg, opts)
		require.NoError(t, err)
		valid, err := csp.Verify(pub, sig, msg, nil)
		require.NoError(t, err)
		require.True(t, valid)
		valid, err = csp.Verify(pub, sig, msg, opts)
		require.NoError(t, err)
		require.True(t, valid)
	}

	valid, err := csp.Verify(pub, cert.Signature, cert.RawTBSCertificate, crypto.SHA256)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestSLHDSABCCSPContext(t *testing.T) {
	pkcs8, cert := loadSLHDSAVectors(t)
	csp := newCompositeTestCSP(t, t.TempDir())
	priv, err := csp.KeyImport(pkcs8, &bccsp.SLHDSAPrivateKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	pub, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	msg := []byte("message")
	opts := &slhdsa.SignerOpts{Context: []byte("context")}

	sig, err := csp.Sign(priv, msg, opts)
	require.NoError(t, err)
	valid, err := csp.Verify(pub, sig, msg, opts)
	require.NoError(t, err)
	require.True(t, valid)
	valid, err = csp.Verify(pub, sig, msg, nil)
	require.NoError(t, err)
	require.False(t, valid)
}

func TestSLHDSABCCSPKeystore(t *testing.T) {
	pkcs8, cert := loadSLHDSAVectors(t)
	msg := []byte("message")
	dir := t.TempDir()
	csp := newCompositeTestCSP(t, dir)

	priv, err := csp.KeyImport(pkcs8, &bccsp.SLHDSAPrivateKeyImportOpts{Temporary: false})
	require.NoError(t, err)
	ski := hex.EncodeToString(priv.SKI())

	stored, err := os.ReadFile(filepath.Join(dir, ski+"_sk"))
	require.NoError(t, err)
	block, _ := pem.Decode(stored)
	require.NotNil(t, block)
	require.Equal(t, "PRIVATE KEY", block.Type)
	require.Equal(t, pkcs8, block.Bytes)

	other := newCompositeTestCSP(t, dir)
	fromCert, err := other.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	loaded, err := other.GetKey(fromCert.SKI())
	require.NoError(t, err)
	require.True(t, loaded.Private())
	sig, err := other.Sign(loaded, msg, nil)
	require.NoError(t, err)
	valid, err := other.Verify(fromCert, sig, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)

	require.NoError(t, os.Rename(filepath.Join(dir, ski+"_sk"), filepath.Join(dir, "renamed")))
	searched, err := newCompositeTestCSP(t, dir).GetKey(priv.SKI())
	require.NoError(t, err)
	require.Equal(t, priv.SKI(), searched.SKI())

	_, err = csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: false})
	require.NoError(t, err)
	stored, err = os.ReadFile(filepath.Join(dir, ski+"_pk"))
	require.NoError(t, err)
	block, _ = pem.Decode(stored)
	require.NotNil(t, block)
	require.Equal(t, "PUBLIC KEY", block.Type)
	require.Equal(t, cert.RawSubjectPublicKeyInfo, block.Bytes)
}

func TestSLHDSABCCSPSigner(t *testing.T) {
	pkcs8, cert := loadSLHDSAVectors(t)
	csp := newCompositeTestCSP(t, t.TempDir())
	priv, err := csp.KeyImport(pkcs8, &bccsp.SLHDSAPrivateKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	msg := []byte("message")

	signer, err := bccspsigner.New(csp, priv)
	require.NoError(t, err)
	pub, ok := signer.Public().(*slhdsa.PublicKey)
	require.True(t, ok)
	spki, err := slhdsa.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	require.Equal(t, cert.RawSubjectPublicKeyInfo, spki)

	sig, err := signer.Sign(rand.Reader, msg, crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, slhdsa.Verify(pub, msg, sig, nil))
}

func TestSLHDSABCCSPRejectsOtherKeys(t *testing.T) {
	csp := newCompositeTestCSP(t, t.TempDir())
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	_, err = csp.KeyImport(pkcs8, &bccsp.SLHDSAPrivateKeyImportOpts{Temporary: true})
	require.Error(t, err)

	spki, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)
	_, err = csp.KeyImport(spki, &bccsp.SLHDSAPKIXPublicKeyImportOpts{Temporary: true})
	require.Error(t, err)

	truncated, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: slhdsa.SHA2_128s.OID},
		PublicKey: asn1.BitString{Bytes: make([]byte, 10), BitLength: 80},
	})
	require.NoError(t, err)
	_, err = csp.KeyImport(&x509.Certificate{RawSubjectPublicKeyInfo: truncated}, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	require.Error(t, err)
}
