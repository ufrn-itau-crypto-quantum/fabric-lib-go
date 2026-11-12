/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package slhdsa

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
	"testing"

	"github.com/stretchr/testify/require"
)

// The origin and checksums of these files are in testdata/rfc9909/SOURCE.
const (
	rfc9909PublicKeyPath   = "testdata/rfc9909/public-key.pem"
	rfc9909PrivateKeyPath  = "testdata/rfc9909/private-key.pem"
	rfc9909CertificatePath = "testdata/rfc9909/certificate.pem"
)

// rfc9909PublicKeyHex is PK.seed || PK.root printed in RFC 9909, Appendix C.1.
const rfc9909PublicKeyHex = "2b8109ec777caa4e1f024ccfcf9497d991805092" +
	"80f4256af2b07af80289b494"

// rfc9909PrivateKeyHex is SK.seed || SK.prf || PK.seed || PK.root printed in RFC 9909, Appendix C.2.
const rfc9909PrivateKeyHex = "a2263bca45860836523160049523d621677fad90d51eb6067a327e0d1e64a501" +
	rfc9909PublicKeyHex

// expectedSizes holds n and the signature size of FIPS 205, Table 2, per parameter set.
var expectedSizes = map[string]struct{ n, sig int }{
	"SLH-DSA-SHA2-128s":  {16, 7856},
	"SLH-DSA-SHA2-128f":  {16, 17088},
	"SLH-DSA-SHA2-192s":  {24, 16224},
	"SLH-DSA-SHA2-192f":  {24, 35664},
	"SLH-DSA-SHA2-256s":  {32, 29792},
	"SLH-DSA-SHA2-256f":  {32, 49856},
	"SLH-DSA-SHAKE-128s": {16, 7856},
	"SLH-DSA-SHAKE-128f": {16, 17088},
	"SLH-DSA-SHAKE-192s": {24, 16224},
	"SLH-DSA-SHAKE-192f": {24, 35664},
	"SLH-DSA-SHAKE-256s": {32, 29792},
	"SLH-DSA-SHAKE-256f": {32, 49856},
}

func readPEM(t *testing.T, path, blockType string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	block, rest := pem.Decode(raw)
	require.NotNil(t, block)
	require.Empty(t, rest)
	require.Equal(t, blockType, block.Type)
	return block.Bytes
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestSLHDSAParameterSetTable(t *testing.T) {
	sets := ParameterSets()
	require.Len(t, sets, 12)
	seen := map[string]bool{}
	for i, ps := range sets {
		require.Equal(t, oidSLHDSA(20+i), ps.OID, ps.Name)
		require.Equal(t, ps.Name, ps.id.String())
		require.False(t, seen[ps.Name])
		seen[ps.Name] = true

		size, ok := expectedSizes[ps.Name]
		require.True(t, ok, ps.Name)
		require.Equal(t, 2*size.n, ps.PublicKeySize(), ps.Name)
		require.Equal(t, 4*size.n, ps.PrivateKeySize(), ps.Name)
		require.Equal(t, size.sig, ps.SignatureSize(), ps.Name)

		got, err := ParameterSetByOID(ps.OID)
		require.NoError(t, err)
		require.Equal(t, ps, got)
	}
}

func TestSLHDSARejectsHashSLHDSAOIDs(t *testing.T) {
	for arc := 35; arc <= 46; arc++ {
		_, err := ParameterSetByOID(oidSLHDSA(arc))
		require.Error(t, err, arc)
	}
}

func TestSLHDSAPublicKeyAgainstRFC9909(t *testing.T) {
	der := readPEM(t, rfc9909PublicKeyPath, "PUBLIC KEY")
	require.True(t, IsPKIXPublicKey(der))

	pub, err := ParsePKIXPublicKey(der)
	require.NoError(t, err)
	require.Equal(t, SHA2_128s, pub.ParameterSet)
	raw, err := pub.Bytes()
	require.NoError(t, err)
	require.Equal(t, decodeHex(t, rfc9909PublicKeyHex), raw)

	got, err := MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	require.Equal(t, der, got)
}

func TestSLHDSAPrivateKeyAgainstRFC9909(t *testing.T) {
	der := readPEM(t, rfc9909PrivateKeyPath, "PRIVATE KEY")

	sk, err := ParsePKCS8PrivateKey(der)
	require.NoError(t, err)
	require.Equal(t, SHA2_128s, sk.ParameterSet)
	raw, err := sk.Bytes()
	require.NoError(t, err)
	require.Equal(t, decodeHex(t, rfc9909PrivateKeyHex), raw)

	got, err := MarshalPKCS8PrivateKey(sk)
	require.NoError(t, err)
	require.Equal(t, der, got)

	pub, err := ParsePKIXPublicKey(readPEM(t, rfc9909PublicKeyPath, "PUBLIC KEY"))
	require.NoError(t, err)
	require.True(t, sk.PublicKey().Equal(pub))
}

func TestSLHDSACertificateAgainstRFC9909(t *testing.T) {
	cert, err := x509.ParseCertificate(readPEM(t, rfc9909CertificatePath, "CERTIFICATE"))
	require.NoError(t, err)

	var tbs struct {
		Raw                asn1.RawContent
		Version            int `asn1:"optional,explicit,default:0,tag:0"`
		SerialNumber       asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
	}
	_, err = asn1.Unmarshal(cert.RawTBSCertificate, &tbs)
	require.NoError(t, err)
	require.Equal(t, SHA2_128s.OID, tbs.SignatureAlgorithm.Algorithm)
	require.Empty(t, tbs.SignatureAlgorithm.Parameters.FullBytes)

	pub, err := ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	raw, err := pub.Bytes()
	require.NoError(t, err)
	require.Equal(t, decodeHex(t, rfc9909PublicKeyHex), raw)

	require.Len(t, cert.Signature, SHA2_128s.SignatureSize())
	require.NoError(t, Verify(pub, cert.RawTBSCertificate, cert.Signature, nil))

	tampered := append([]byte(nil), cert.RawTBSCertificate...)
	tampered[len(tampered)-1] ^= 1
	require.Error(t, Verify(pub, tampered, cert.Signature, nil))
	require.Error(t, Verify(pub, cert.RawTBSCertificate, cert.Signature, []byte("ctx")))
}

func TestSLHDSARoundTrip(t *testing.T) {
	for _, ps := range ParameterSets() {
		t.Run(ps.Name, func(t *testing.T) {
			t.Parallel()
			msg := []byte("message")
			sk, err := GenerateKey(ps)
			require.NoError(t, err)

			skDER, err := MarshalPKCS8PrivateKey(sk)
			require.NoError(t, err)
			sk2, err := ParsePKCS8PrivateKey(skDER)
			require.NoError(t, err)
			require.True(t, sk.Equal(sk2))

			pkDER, err := MarshalPKIXPublicKey(sk.PublicKey())
			require.NoError(t, err)
			pub, err := ParsePKIXPublicKey(pkDER)
			require.NoError(t, err)
			require.True(t, sk.PublicKey().Equal(pub))

			sig, err := sk2.Sign(rand.Reader, msg, nil)
			require.NoError(t, err)
			require.Len(t, sig, ps.SignatureSize())
			require.NoError(t, Verify(pub, msg, sig, nil))
			require.Error(t, Verify(pub, []byte("other"), sig, nil))
		})
	}
}

func TestSLHDSAContext(t *testing.T) {
	msg := []byte("message")
	ctx := []byte("context")
	sk, err := GenerateKey(SHA2_128f)
	require.NoError(t, err)

	sig, err := sk.Sign(nil, msg, &SignerOpts{Context: ctx})
	require.NoError(t, err)
	require.NoError(t, Verify(sk.PublicKey(), msg, sig, ctx))
	require.Error(t, Verify(sk.PublicKey(), msg, sig, nil))
}

func TestSLHDSASignIsRandomized(t *testing.T) {
	msg := []byte("message")
	sk, err := GenerateKey(SHA2_128f)
	require.NoError(t, err)

	sig1, err := sk.Sign(nil, msg, nil)
	require.NoError(t, err)
	sig2, err := sk.Sign(nil, msg, nil)
	require.NoError(t, err)
	require.NotEqual(t, sig1, sig2)
}

func TestSLHDSASignRejectsInvalidOptions(t *testing.T) {
	msg := []byte("message")
	sk, err := GenerateKey(SHA2_128f)
	require.NoError(t, err)

	_, err = sk.Sign(rand.Reader, msg, crypto.SHA256)
	require.Error(t, err)
	_, err = sk.Sign(rand.Reader, msg, &SignerOpts{Context: make([]byte, 256)})
	require.Error(t, err)
	_, err = sk.Sign(rand.Reader, msg, crypto.Hash(0))
	require.NoError(t, err)
}

func TestSLHDSAVerifyRejectsOtherKey(t *testing.T) {
	msg := []byte("message")
	sk, err := GenerateKey(SHA2_128f)
	require.NoError(t, err)
	other, err := GenerateKey(SHA2_128f)
	require.NoError(t, err)

	sig, err := sk.Sign(nil, msg, nil)
	require.NoError(t, err)
	require.Error(t, Verify(other.PublicKey(), msg, sig, nil))
	require.Error(t, Verify(sk.PublicKey(), msg, sig[:len(sig)-1], nil))
}

func TestSLHDSAParseRejectsWrongSize(t *testing.T) {
	pk := decodeHex(t, rfc9909PublicKeyHex)
	sk := decodeHex(t, rfc9909PrivateKeyHex)

	_, err := ParsePublicKey(SHA2_192s, pk)
	require.Error(t, err)
	_, err = ParsePublicKey(SHA2_128s, pk[:len(pk)-1])
	require.Error(t, err)
	_, err = ParsePrivateKey(SHA2_192s, sk)
	require.Error(t, err)
	_, err = ParsePrivateKey(SHA2_128s, append(sk, 0))
	require.Error(t, err)
}

func TestSLHDSAPKIXRejectsOtherKeys(t *testing.T) {
	pk := decodeHex(t, rfc9909PublicKeyHex)
	spki := func(ai pkix.AlgorithmIdentifier) []byte {
		der, err := asn1.Marshal(subjectPublicKeyInfo{
			Algorithm: ai,
			PublicKey: asn1.BitString{Bytes: pk, BitLength: len(pk) * 8},
		})
		require.NoError(t, err)
		return der
	}

	hashOID := spki(pkix.AlgorithmIdentifier{Algorithm: oidSLHDSA(35)})
	require.False(t, IsPKIXPublicKey(hashOID))
	_, err := ParsePKIXPublicKey(hashOID)
	require.ErrorIs(t, err, ErrNotSLHDSA)

	withParams := spki(pkix.AlgorithmIdentifier{Algorithm: SHA2_128s.OID, Parameters: asn1.NullRawValue})
	_, err = ParsePKIXPublicKey(withParams)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNotSLHDSA)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecSPKI, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)
	require.False(t, IsPKIXPublicKey(ecSPKI))
	_, err = ParsePKIXPublicKey(ecSPKI)
	require.ErrorIs(t, err, ErrNotSLHDSA)
}

func TestSLHDSAPKCS8WithPublicKey(t *testing.T) {
	sk := decodeHex(t, rfc9909PrivateKeyHex)
	pk := decodeHex(t, rfc9909PublicKeyHex)
	encode := func(pub []byte) []byte {
		der, err := asn1.Marshal(oneAsymmetricKey{
			Version:    1,
			Algorithm:  pkix.AlgorithmIdentifier{Algorithm: SHA2_128s.OID},
			PrivateKey: sk,
			PublicKey:  asn1.BitString{Bytes: pub, BitLength: len(pub) * 8},
		})
		require.NoError(t, err)
		return der
	}

	parsed, err := ParsePKCS8PrivateKey(encode(pk))
	require.NoError(t, err)
	raw, err := parsed.Bytes()
	require.NoError(t, err)
	require.Equal(t, sk, raw)

	wrong := append([]byte(nil), pk...)
	wrong[0] ^= 1
	_, err = ParsePKCS8PrivateKey(encode(wrong))
	require.Error(t, err)
}

func BenchmarkSLHDSA(b *testing.B) {
	msg := make([]byte, 1024)
	for _, ps := range ParameterSets() {
		sk, err := GenerateKey(ps)
		require.NoError(b, err)
		sig, err := sk.Sign(nil, msg, nil)
		require.NoError(b, err)

		b.Run(ps.Name+"/KeyGen", func(b *testing.B) {
			for b.Loop() {
				_, _ = GenerateKey(ps)
			}
		})
		b.Run(ps.Name+"/Sign", func(b *testing.B) {
			for b.Loop() {
				_, _ = sk.Sign(nil, msg, nil)
			}
		})
		b.Run(ps.Name+"/Verify", func(b *testing.B) {
			for b.Loop() {
				_ = Verify(sk.PublicKey(), msg, sig, nil)
			}
		})
	}
}
