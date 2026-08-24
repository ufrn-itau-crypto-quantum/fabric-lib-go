/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	bccspsigner "github.com/hyperledger/fabric-lib-go/bccsp/signer"
	"github.com/stretchr/testify/require"
)

// mldsaParameterSets is the table driving every ML-DSA test, so all three security
// categories go through the same paths.
var mldsaParameterSets = []struct {
	name    string
	params  mldsa.Parameters
	genOpts bccsp.KeyGenOpts
}{
	{"ML-DSA-44", mldsa.MLDSA44(), &bccsp.MLDSA44KeyGenOpts{Temporary: true}},
	{"ML-DSA-65", mldsa.MLDSA65(), &bccsp.MLDSA65KeyGenOpts{Temporary: true}},
	{"ML-DSA-87", mldsa.MLDSA87(), &bccsp.MLDSA87KeyGenOpts{Temporary: true}},
}

func TestVerifyMLDSA(t *testing.T) {
	t.Parallel()

	for _, ps := range mldsaParameterSets {
		t.Run(ps.name, func(t *testing.T) {
			t.Parallel()

			lowLevelKey, err := mldsa.GenerateKey(ps.params)
			require.NoError(t, err)

			msg := []byte("hello world")
			sigma, err := signMLDSA(lowLevelKey, msg, nil)
			require.NoError(t, err)
			require.Len(t, sigma, ps.params.SignatureSize())

			valid, err := verifyMLDSA(lowLevelKey.PublicKey(), sigma, msg, nil)
			require.NoError(t, err)
			require.True(t, valid)

			// A different message must not verify.
			valid, err = verifyMLDSA(lowLevelKey.PublicKey(), sigma, []byte("goodbye world"), nil)
			require.NoError(t, err)
			require.False(t, valid)
		})
	}
}

// TestMLDSASignIgnoresHashOpts pins the opts normalization. crypto/mldsa rejects any
// SignerOpts whose HashFunc is not zero; crypto.Hash values are valid crypto.SignerOpts and
// reach csp.Sign through the bccsp/signer adapter, so they must not break signing.
func TestMLDSASignIgnoresHashOpts(t *testing.T) {
	t.Parallel()

	lowLevelKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	msg := []byte("hello world")
	sigma, err := signMLDSA(lowLevelKey, msg, crypto.SHA256)
	require.NoError(t, err, "a hash-bearing SignerOpts must not break signing")

	valid, err := verifyMLDSA(lowLevelKey.PublicKey(), sigma, msg, crypto.SHA256)
	require.NoError(t, err)
	require.True(t, valid)
}

// TestMLDSASignWithContext covers the context string, which only crypto/mldsa exposes.
func TestMLDSASignWithContext(t *testing.T) {
	t.Parallel()

	lowLevelKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	msg := []byte("hello world")
	opts := &mldsa.Options{Context: "fabric-test"}
	sigma, err := signMLDSA(lowLevelKey, msg, opts)
	require.NoError(t, err)

	valid, err := verifyMLDSA(lowLevelKey.PublicKey(), sigma, msg, opts)
	require.NoError(t, err)
	require.True(t, valid)

	// A different context must not verify.
	valid, err = verifyMLDSA(lowLevelKey.PublicKey(), sigma, msg, &mldsa.Options{Context: "other"})
	require.NoError(t, err)
	require.False(t, valid)
}

func TestMLDSASignerSign(t *testing.T) {
	t.Parallel()

	signer := &mldsaSigner{}
	verifierPrivateKey := &mldsaPrivateKeyVerifier{}
	verifierPublicKey := &mldsaPublicKeyKeyVerifier{}

	for _, ps := range mldsaParameterSets {
		t.Run(ps.name, func(t *testing.T) {
			t.Parallel()

			lowLevelKey, err := mldsa.GenerateKey(ps.params)
			require.NoError(t, err)
			k := &mldsaPrivateKey{lowLevelKey}
			pk, err := k.PublicKey()
			require.NoError(t, err)

			msg := []byte("hello world")
			sigma, err := signer.Sign(k, msg, nil)
			require.NoError(t, err)

			valid, err := verifierPrivateKey.Verify(k, sigma, msg, nil)
			require.NoError(t, err)
			require.True(t, valid)

			valid, err = verifierPublicKey.Verify(pk, sigma, msg, nil)
			require.NoError(t, err)
			require.True(t, valid)
		})
	}
}

func TestMLDSAPrivateKey(t *testing.T) {
	t.Parallel()

	lowLevelKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	k := &mldsaPrivateKey{lowLevelKey}

	require.False(t, k.Symmetric())
	require.True(t, k.Private())

	_, err = k.Bytes()
	require.Error(t, err)
	require.Contains(t, err.Error(), "Not supported.")

	k.privKey = nil
	require.Nil(t, k.SKI())
	k.privKey = lowLevelKey

	// The SKI must be the hash of the public key, not of the private one.
	raw := lowLevelKey.PublicKey().Bytes()
	hash := sha256.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	require.Equal(t, ski2, k.SKI())

	pk, err := k.PublicKey()
	require.NoError(t, err)
	require.NotNil(t, pk)
}

func TestMLDSAPublicKey(t *testing.T) {
	t.Parallel()

	lowLevelKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	k := &mldsaPublicKey{lowLevelKey.PublicKey()}

	require.False(t, k.Symmetric())
	require.False(t, k.Private())

	k.pubKey = nil
	require.Nil(t, k.SKI())
	k.pubKey = lowLevelKey.PublicKey()

	raw := k.pubKey.Bytes()
	hash := sha256.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	require.Equal(t, ski2, k.SKI())

	pk, err := k.PublicKey()
	require.NoError(t, err)
	require.Equal(t, k, pk)

	// Bytes must be the PKIX encoding, which is what makes bccsp/signer.New work.
	bytes, err := k.Bytes()
	require.NoError(t, err)
	bytes2, err := x509.MarshalPKIXPublicKey(k.pubKey)
	require.NoError(t, err)
	require.Equal(t, bytes2, bytes)
}

// TestMLDSASKIMatchesBetweenPrivateAndPublic pins the invariant the keystore depends on:
// GetKey looks a private key up by the SKI computed from the public key found in a
// certificate, so the two must agree.
func TestMLDSASKIMatchesBetweenPrivateAndPublic(t *testing.T) {
	t.Parallel()

	for _, ps := range mldsaParameterSets {
		t.Run(ps.name, func(t *testing.T) {
			t.Parallel()

			lowLevelKey, err := mldsa.GenerateKey(ps.params)
			require.NoError(t, err)

			sk := &mldsaPrivateKey{lowLevelKey}
			pk, err := sk.PublicKey()
			require.NoError(t, err)

			require.Equal(t, sk.SKI(), pk.SKI())
			require.NotEmpty(t, sk.SKI())
		})
	}
}

// TestMLDSACertificateRoundTrip is the end-to-end proof that ML-DSA keys held by the BCCSP
// can issue and verify a real X.509 certificate: generate through the CSP, adapt to a
// crypto.Signer, sign a certificate, parse it back and check the signature. This is what
// the circl-based implementation could not do, because its public key bytes were not a
// SubjectPublicKeyInfo that crypto/x509 could parse.
func TestMLDSACertificateRoundTrip(t *testing.T) {
	t.Parallel()

	expectedSigAlgo := map[string]x509.SignatureAlgorithm{
		"ML-DSA-44": x509.MLDSA44,
		"ML-DSA-65": x509.MLDSA65,
		"ML-DSA-87": x509.MLDSA87,
	}

	for _, ps := range mldsaParameterSets {
		t.Run(ps.name, func(t *testing.T) {
			t.Parallel()

			csp, cleanup := newTestCSP(t)
			defer cleanup()

			k, err := csp.KeyGen(ps.genOpts)
			require.NoError(t, err)

			// The BCCSP -> crypto.Signer adapter parses Key.Bytes() as PKIX.
			cryptoSigner, err := bccspsigner.New(csp, k)
			require.NoError(t, err, "signer.New must accept an ML-DSA key")

			template := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: ps.name},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(time.Hour),
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
				BasicConstraintsValid: true,
				IsCA:                  true,
			}

			certDER, err := x509.CreateCertificate(rand.Reader, template, template, cryptoSigner.Public(), cryptoSigner)
			require.NoError(t, err)

			cert, err := x509.ParseCertificate(certDER)
			require.NoError(t, err)
			require.Equal(t, x509.MLDSA, cert.PublicKeyAlgorithm)
			require.Equal(t, expectedSigAlgo[ps.name], cert.SignatureAlgorithm)
			require.NoError(t, cert.CheckSignatureFrom(cert))

			// The public key parsed out of the certificate must round-trip back into the
			// CSP and land on the same SKI, which is how a private key is found again.
			importedPK, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
			require.NoError(t, err)
			require.Equal(t, k.SKI(), importedPK.SKI())
		})
	}
}

func newTestCSP(t *testing.T) (bccsp.BCCSP, func()) {
	t.Helper()

	ks, err := NewFileBasedKeyStore(nil, t.TempDir(), false)
	require.NoError(t, err)
	csp, err := NewWithParams(256, "SHA2", ks)
	require.NoError(t, err)

	return csp, func() {}
}
