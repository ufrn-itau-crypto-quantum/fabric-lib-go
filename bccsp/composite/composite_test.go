/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// A origem e o checksum deste arquivo estão em testdata/composite-sigs-19/SOURCE.
const compositeVectorsPath = "testdata/composite-sigs-19/testvectors.json"

type compositeVectorFile struct {
	M     string            `json:"m"`
	Ctx   string            `json:"ctx"`
	Tests []compositeVector `json:"tests"`
}

type compositeVector struct {
	TcID         string `json:"tcId"`
	PK           string `json:"pk"`
	SK           string `json:"sk"`
	S            string `json:"s"`
	SWithContext string `json:"sWithContext"`
	SKPKCS8      string `json:"sk_pkcs8"`
	X5c          string `json:"x5c"`
}

// ecdsaSigValue é o Ecdsa-Sig-Value da RFC 3279, seção 2.2.3.
type ecdsaSigValue struct {
	R, S *big.Int
}

// compositeFixture guarda valores copiados do draft.
type compositeFixture struct {
	tcID      string // nome do vetor no testvectors.json, como no apêndice E do draft
	oid       string // OID do algoritmo, seção 7 do draft
	label     string // rótulo de assinatura incluído no M', seção 6 do draft
	hash      crypto.Hash
	tradHash  crypto.Hash // hash do ECDSA sobre o M', seção 6 do draft
	level     int
	curve     elliptic.Curve
	pubKeyLen int // ponto EC uncompressed: byte 0x04 + duas coordenadas
	pkLen     int // tamanho da chave pública composta, tabela 4 do draft
	skLen     int // tamanho da chave privada composta, tabela 4 do draft
}

var compositeFixtures = []compositeFixture{
	{
		tcID: "id-MLDSA44-ECDSA-P256-SHA256", oid: "1.3.6.1.5.5.7.6.40", label: "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
		hash: crypto.SHA256, tradHash: crypto.SHA256, level: 44, curve: elliptic.P256(), pubKeyLen: 65, pkLen: 1377, skLen: 83,
	},
	{
		tcID: "id-MLDSA65-ECDSA-P384-SHA512", oid: "1.3.6.1.5.5.7.6.46", label: "COMPSIG-MLDSA65-ECDSA-P384-SHA512",
		hash: crypto.SHA512, tradHash: crypto.SHA384, level: 65, curve: elliptic.P384(), pubKeyLen: 97, pkLen: 2049, skLen: 96,
	},
	{
		tcID: "id-MLDSA87-ECDSA-P384-SHA512", oid: "1.3.6.1.5.5.7.6.49", label: "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
		hash: crypto.SHA512, tradHash: crypto.SHA384, level: 87, curve: elliptic.P384(), pubKeyLen: 97, pkLen: 2689, skLen: 96,
	},
}

func loadCompositeVectors(t *testing.T) compositeVectorFile {
	t.Helper()
	raw, err := os.ReadFile(compositeVectorsPath)
	require.NoError(t, err)
	var file compositeVectorFile
	require.NoError(t, json.Unmarshal(raw, &file))
	return file
}

func (f compositeVectorFile) find(t *testing.T, tcID string) compositeVector {
	t.Helper()
	for _, tc := range f.Tests {
		if tc.TcID == tcID {
			return tc
		}
	}
	t.Fatalf("test vectors do not contain tcId %q", tcID)
	return compositeVector{}
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

func fixtureAlgorithm(t *testing.T, fx compositeFixture) Algorithm {
	t.Helper()
	alg, err := AlgorithmForLevel(fx.level)
	require.NoError(t, err)
	return alg
}

func TestCompositeVectorsChecksum(t *testing.T) {
	raw, err := os.ReadFile(compositeVectorsPath)
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	require.Equal(t, "a60f697f9fd94c3cd5e4501a40c4396d9a9ffc7cf0f8a1ddd87dedbb46a7abf0", hex.EncodeToString(sum[:]))
}

func TestCompositeAlgorithmTable(t *testing.T) {
	for _, fx := range compositeFixtures {
		byLevel, err := AlgorithmForLevel(fx.level)
		require.NoError(t, err)
		require.Equal(t, fx.oid, byLevel.OID.String())
		require.Equal(t, fx.label, byLevel.Label)
		require.Equal(t, fx.hash, byLevel.Hash)
		require.Equal(t, fx.tradHash, byLevel.TraditionalHash)
		require.Equal(t, fx.curve, byLevel.Curve)

		byOID, err := AlgorithmByOID(byLevel.OID)
		require.NoError(t, err)
		require.Equal(t, fx.level, byOID.MLDSALevel)
	}

	_, err := AlgorithmForLevel(88)
	require.Error(t, err)
	_, err = AlgorithmByOID(asn1.ObjectIdentifier{1, 2, 3})
	require.Error(t, err)
}

func TestCompositePrefix(t *testing.T) {
	require.Equal(t, "436f6d706f73697465416c676f726974686d5369676e61747572657332303235", hex.EncodeToString(Prefix))
}

func TestCompositePublicKeyAgainstVectors(t *testing.T) {
	vectors := loadCompositeVectors(t)
	for _, fx := range compositeFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			alg := fixtureAlgorithm(t, fx)
			pk := decodeB64(t, vectors.find(t, fx.tcID).PK)

			mldsaPK, tradPK, err := DeserializePublicKey(alg, pk)
			require.NoError(t, err)

			require.Len(t, tradPK, fx.pubKeyLen)
			x, y := elliptic.Unmarshal(fx.curve, tradPK)
			require.NotNil(t, x)
			require.True(t, fx.curve.IsOnCurve(x, y))

			_, err = mldsa.NewPublicKey(mldsaParameters(t, fx.level), mldsaPK)
			require.NoError(t, err)

			require.Equal(t, pk, SerializePublicKey(mldsaPK, tradPK))
		})
	}
}

func TestCompositePrivateKeyAgainstVectors(t *testing.T) {
	vectors := loadCompositeVectors(t)
	for _, fx := range compositeFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			alg := fixtureAlgorithm(t, fx)
			vector := vectors.find(t, fx.tcID)
			sk := decodeB64(t, vector.SK)
			pk := decodeB64(t, vector.PK)

			mldsaSeed, tradSK, err := DeserializePrivateKey(sk)
			require.NoError(t, err)
			require.Len(t, mldsaSeed, mldsa.PrivateKeySize)

			ecKey, err := x509.ParseECPrivateKey(tradSK)
			require.NoError(t, err)
			require.Equal(t, fx.curve, ecKey.Curve)

			mldsaKey, err := mldsa.NewPrivateKey(mldsaParameters(t, fx.level), mldsaSeed)
			require.NoError(t, err)

			mldsaPK, tradPK, err := DeserializePublicKey(alg, pk)
			require.NoError(t, err)
			require.Equal(t, tradPK, elliptic.Marshal(fx.curve, ecKey.X, ecKey.Y)) //nolint:staticcheck
			require.Equal(t, mldsaPK, mldsaKey.PublicKey().Bytes())

			require.Equal(t, sk, SerializePrivateKey(mldsaSeed, tradSK))
		})
	}
}

func TestCompositeSignatureValueAgainstVectors(t *testing.T) {
	vectors := loadCompositeVectors(t)
	for _, fx := range compositeFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			alg := fixtureAlgorithm(t, fx)
			vector := vectors.find(t, fx.tcID)
			mldsaSize, err := mldsaSignatureSize(fx.level)
			require.NoError(t, err)

			for name, b64 := range map[string]string{"s": vector.S, "sWithContext": vector.SWithContext} {
				t.Run(name, func(t *testing.T) {
					raw := decodeB64(t, b64)

					mldsaSig, tradSig, err := DeserializeSignatureValue(alg, raw)
					require.NoError(t, err)
					require.Len(t, mldsaSig, mldsaSize)

					var sig ecdsaSigValue
					rest, err := asn1.Unmarshal(tradSig, &sig)
					require.NoError(t, err)
					require.Empty(t, rest)

					require.Equal(t, raw, SerializeSignatureValue(mldsaSig, tradSig))
				})
			}
		})
	}
}

func TestCompositeMessageRepresentative(t *testing.T) {
	vectors := loadCompositeVectors(t)
	m := decodeB64(t, vectors.M)
	ctx := decodeB64(t, vectors.Ctx)

	for _, fx := range compositeFixtures {
		alg := fixtureAlgorithm(t, fx)
		for name, c := range map[string][]byte{"empty ctx": nil, "vector ctx": ctx} {
			t.Run(fx.tcID+"/"+name, func(t *testing.T) {
				got, err := MessageRepresentative(alg, c, m)
				require.NoError(t, err)

				want := "CompositeAlgorithmSignatures2025" + fx.label + string([]byte{byte(len(c))}) + string(c) + string(digest(t, fx.hash, m))
				require.Equal(t, want, string(got))
			})
		}
	}

	_, err := MessageRepresentative(fixtureAlgorithm(t, compositeFixtures[0]), make([]byte, 256), m)
	require.Error(t, err)
}

func TestCompositeDeserializeRejectsShortInput(t *testing.T) {
	alg := fixtureAlgorithm(t, compositeFixtures[0])

	_, _, err := DeserializePublicKey(alg, make([]byte, mldsa.MLDSA44PublicKeySize))
	require.Error(t, err)
	_, _, err = DeserializePrivateKey(make([]byte, mldsa.PrivateKeySize))
	require.Error(t, err)
	_, _, err = DeserializeSignatureValue(alg, make([]byte, mldsa.MLDSA44SignatureSize))
	require.Error(t, err)
}

func TestCompositeKeysAgainstVectors(t *testing.T) {
	vectors := loadCompositeVectors(t)
	for _, fx := range compositeFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			alg := fixtureAlgorithm(t, fx)
			vector := vectors.find(t, fx.tcID)
			pk := decodeB64(t, vector.PK)
			sk := decodeB64(t, vector.SK)

			pub, err := ParsePublicKey(alg, pk)
			require.NoError(t, err)
			gotPK, err := pub.Bytes()
			require.NoError(t, err)
			require.Equal(t, pk, gotPK)

			priv, err := ParsePrivateKey(alg, sk)
			require.NoError(t, err)
			gotSK, err := priv.Bytes()
			require.NoError(t, err)
			require.Equal(t, sk, gotSK)
			require.True(t, priv.PublicKey().Equal(pub))
		})
	}
}

func TestCompositeVerifyAgainstVectors(t *testing.T) {
	vectors := loadCompositeVectors(t)
	m := decodeB64(t, vectors.M)
	ctx := decodeB64(t, vectors.Ctx)
	for _, fx := range compositeFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			pub := vectorPublicKey(t, vectors, fx)
			vector := vectors.find(t, fx.tcID)
			s := decodeB64(t, vector.S)
			sCtx := decodeB64(t, vector.SWithContext)

			require.NoError(t, Verify(pub, m, s, nil))
			require.NoError(t, Verify(pub, m, sCtx, ctx))

			require.Error(t, Verify(pub, m, s, ctx))
			require.Error(t, Verify(pub, m, sCtx, nil))
			require.Error(t, Verify(pub, append(append([]byte{}, m...), '!'), s, nil))
		})
	}
}

func TestCompositeVerifyRequiresBothComponents(t *testing.T) {
	vectors := loadCompositeVectors(t)
	m := decodeB64(t, vectors.M)
	for _, fx := range compositeFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			alg := fixtureAlgorithm(t, fx)
			pub := vectorPublicKey(t, vectors, fx)
			vector := vectors.find(t, fx.tcID)
			s := decodeB64(t, vector.S)
			mldsaSig, tradSig, err := DeserializeSignatureValue(alg, s)
			require.NoError(t, err)
			mldsaCtx, tradCtx, err := DeserializeSignatureValue(alg, decodeB64(t, vector.SWithContext))
			require.NoError(t, err)

			require.Error(t, Verify(pub, m, SerializeSignatureValue(mldsaSig, tradCtx), nil))
			require.Error(t, Verify(pub, m, SerializeSignatureValue(mldsaCtx, tradSig), nil))

			require.Error(t, Verify(pub, m, flipByte(s, 0), nil))
			require.Error(t, Verify(pub, m, flipByte(s, len(s)-1), nil))
			require.Error(t, Verify(pub, m, s[:len(s)-1], nil))
		})
	}
}

func TestCompositeSignVerifiesWithVectorKeys(t *testing.T) {
	vectors := loadCompositeVectors(t)
	m := decodeB64(t, vectors.M)
	ctx := decodeB64(t, vectors.Ctx)
	for _, fx := range compositeFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			priv, err := ParsePrivateKey(fixtureAlgorithm(t, fx), decodeB64(t, vectors.find(t, fx.tcID).SK))
			require.NoError(t, err)
			pub := vectorPublicKey(t, vectors, fx)

			sig, err := priv.Sign(rand.Reader, m, nil)
			require.NoError(t, err)
			require.NoError(t, Verify(pub, m, sig, nil))

			sig, err = priv.Sign(rand.Reader, m, &SignerOpts{Context: ctx})
			require.NoError(t, err)
			require.NoError(t, Verify(pub, m, sig, ctx))
		})
	}
}

func TestCompositeGenerateKey(t *testing.T) {
	m := []byte("mensagem")
	for _, fx := range compositeFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			alg := fixtureAlgorithm(t, fx)
			a, err := GenerateKey(alg)
			require.NoError(t, err)
			b, err := GenerateKey(alg)
			require.NoError(t, err)
			require.False(t, a.PublicKey().Equal(b.PublicKey()))
			require.False(t, a.PublicKey().Equal(&PublicKey{Algorithm: alg, MLDSA: a.MLDSA.PublicKey(), Traditional: &b.Traditional.PublicKey}))
			require.False(t, a.PublicKey().Equal(&PublicKey{Algorithm: alg, MLDSA: b.MLDSA.PublicKey(), Traditional: &a.Traditional.PublicKey}))

			sk, err := a.Bytes()
			require.NoError(t, err)
			require.Len(t, sk, fx.skLen)
			pk, err := a.PublicKey().Bytes()
			require.NoError(t, err)
			require.Len(t, pk, fx.pkLen)

			parsed, err := ParsePrivateKey(alg, sk)
			require.NoError(t, err)
			require.True(t, parsed.PublicKey().Equal(a.PublicKey()))

			sig, err := a.Sign(nil, m, nil)
			require.NoError(t, err)
			require.NoError(t, Verify(a.PublicKey(), m, sig, nil))
			require.Error(t, Verify(b.PublicKey(), m, sig, nil))
		})
	}
}

func TestCompositeLabelBindsTheAlgorithm(t *testing.T) {
	m := []byte("mensagem")
	priv, err := GenerateKey(fixtureAlgorithm(t, compositeFixtures[1]))
	require.NoError(t, err)
	sig, err := priv.Sign(rand.Reader, m, nil)
	require.NoError(t, err)
	require.NoError(t, Verify(priv.PublicKey(), m, sig, nil))

	other := priv.PublicKey()
	other.Algorithm.Label = compositeFixtures[2].label
	require.Error(t, Verify(other, m, sig, nil))
}

func TestCompositeSignRejectsInvalidOptions(t *testing.T) {
	m := []byte("mensagem")
	priv, err := GenerateKey(fixtureAlgorithm(t, compositeFixtures[0]))
	require.NoError(t, err)

	_, err = priv.Sign(rand.Reader, m, crypto.SHA256)
	require.Error(t, err)
	_, err = priv.Sign(rand.Reader, m, &SignerOpts{Context: make([]byte, 256)})
	require.Error(t, err)
	_, err = priv.Sign(rand.Reader, m, crypto.Hash(0))
	require.NoError(t, err)
}

func TestCompositeParseRejectsOtherAlgorithm(t *testing.T) {
	vectors := loadCompositeVectors(t)
	vector := vectors.find(t, compositeFixtures[0].tcID)
	alg65 := fixtureAlgorithm(t, compositeFixtures[1])

	_, err := ParsePublicKey(alg65, decodeB64(t, vector.PK))
	require.Error(t, err)
	_, err = ParsePrivateKey(alg65, decodeB64(t, vector.SK))
	require.Error(t, err)
}

func TestCompositePKCS8AgainstVectors(t *testing.T) {
	vectors := loadCompositeVectors(t)
	for _, fx := range compositeFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			vector := vectors.find(t, fx.tcID)
			der := decodeB64(t, vector.SKPKCS8)

			sk, err := ParsePKCS8PrivateKey(der)
			require.NoError(t, err)
			raw, err := sk.Bytes()
			require.NoError(t, err)
			require.Equal(t, decodeB64(t, vector.SK), raw)

			got, err := MarshalPKCS8PrivateKey(sk)
			require.NoError(t, err)
			require.Equal(t, der, got)
		})
	}
}

func TestCompositePKIXAgainstVectors(t *testing.T) {
	vectors := loadCompositeVectors(t)
	for _, fx := range compositeFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			vector := vectors.find(t, fx.tcID)
			cert, err := x509.ParseCertificate(decodeB64(t, vector.X5c))
			require.NoError(t, err)

			pub, err := ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
			require.NoError(t, err)
			raw, err := pub.Bytes()
			require.NoError(t, err)
			require.Equal(t, decodeB64(t, vector.PK), raw)

			got, err := MarshalPKIXPublicKey(pub)
			require.NoError(t, err)
			require.Equal(t, cert.RawSubjectPublicKeyInfo, got)

			require.NoError(t, Verify(pub, cert.RawTBSCertificate, cert.Signature, nil))
		})
	}
}

func TestCompositePKIXRejectsOtherKeys(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spki, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)
	_, err = ParsePKIXPublicKey(spki)
	require.True(t, errors.Is(err, ErrNotComposite))

	pkcs8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	_, err = ParsePKCS8PrivateKey(pkcs8)
	require.True(t, errors.Is(err, ErrNotComposite))

	priv, err := GenerateKey(fixtureAlgorithm(t, compositeFixtures[0]))
	require.NoError(t, err)
	raw, err := priv.PublicKey().Bytes()
	require.NoError(t, err)

	withNull, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA44ECDSAP256SHA256, Parameters: asn1.NullRawValue},
		PublicKey: asn1.BitString{Bytes: raw, BitLength: len(raw) * 8},
	})
	require.NoError(t, err)
	_, err = ParsePKIXPublicKey(withNull)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrNotComposite))

	skRaw, err := priv.Bytes()
	require.NoError(t, err)
	version1, err := asn1.Marshal(pkcs8PrivateKey{Version: 1, Algorithm: pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA44ECDSAP256SHA256}, PrivateKey: skRaw})
	require.NoError(t, err)
	_, err = ParsePKCS8PrivateKey(version1)
	require.Error(t, err)
}

func TestCompositeCertificateSignatureAgainstVectors(t *testing.T) {
	vectors := loadCompositeVectors(t)
	for _, fx := range compositeFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			alg := fixtureAlgorithm(t, fx)
			cert, err := x509.ParseCertificate(decodeB64(t, vectors.find(t, fx.tcID).X5c))
			require.NoError(t, err)
			pub, err := ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
			require.NoError(t, err)
			require.NoError(t, CheckCertificateSignature(cert, pub))

			algID, err := AlgorithmIdentifier(alg)
			require.NoError(t, err)
			var outer certificateOuter
			_, err = asn1.Unmarshal(cert.Raw, &outer)
			require.NoError(t, err)
			require.Equal(t, outer.SignatureAlgorithm.FullBytes, algID)
			var spki struct {
				Algorithm asn1.RawValue
				PublicKey asn1.BitString
			}
			_, err = asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki)
			require.NoError(t, err)
			require.Equal(t, spki.Algorithm.FullBytes, algID)
		})
	}
}

func TestCompositeCertificateSignatureRejects(t *testing.T) {
	vectors := loadCompositeVectors(t)
	cert, err := x509.ParseCertificate(decodeB64(t, vectors.find(t, compositeFixtures[1].tcID).X5c))
	require.NoError(t, err)
	pub, err := ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	var outer certificateOuter
	_, err = asn1.Unmarshal(cert.Raw, &outer)
	require.NoError(t, err)

	rebuild := func(o certificateOuter) *x509.Certificate {
		der, err := asn1.Marshal(o)
		require.NoError(t, err)
		return &x509.Certificate{Raw: der}
	}

	tampered := outer
	tbs := append([]byte{}, outer.TBS.FullBytes...)
	tbs[len(tbs)-1] ^= 0x01
	tampered.TBS = asn1.RawValue{FullBytes: tbs}
	require.Error(t, CheckCertificateSignature(rebuild(tampered), pub))

	withNull, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA65ECDSAP384SHA512, Parameters: asn1.NullRawValue})
	require.NoError(t, err)
	nullParams := outer
	nullParams.SignatureAlgorithm = asn1.RawValue{FullBytes: withNull}
	require.Error(t, CheckCertificateSignature(rebuild(nullParams), pub))

	otherID, err := AlgorithmIdentifier(fixtureAlgorithm(t, compositeFixtures[2]))
	require.NoError(t, err)
	otherAlg := outer
	otherAlg.SignatureAlgorithm = asn1.RawValue{FullBytes: otherID}
	require.Error(t, CheckCertificateSignature(rebuild(otherAlg), pub))

	otherPub, err := ParsePKIXPublicKey(mustParseCert(t, vectors.find(t, compositeFixtures[0].tcID).X5c).RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	require.ErrorContains(t, CheckCertificateSignature(cert, otherPub), "but the issuer key is")

	priv, err := ParsePrivateKey(fixtureAlgorithm(t, compositeFixtures[1]), decodeB64(t, vectors.find(t, compositeFixtures[1].tcID).SK))
	require.NoError(t, err)
	algID65, err := AlgorithmIdentifier(fixtureAlgorithm(t, compositeFixtures[1]))
	require.NoError(t, err)
	algID87, err := AlgorithmIdentifier(fixtureAlgorithm(t, compositeFixtures[2]))
	require.NoError(t, err)
	i := bytes.Index(outer.TBS.FullBytes, algID65)
	require.Positive(t, i)
	innerChanged := append(append(append([]byte{}, outer.TBS.FullBytes[:i]...), algID87...), outer.TBS.FullBytes[i+len(algID87):]...)
	sig, err := priv.Sign(rand.Reader, innerChanged, nil)
	require.NoError(t, err)
	require.NoError(t, Verify(pub, innerChanged, sig, nil))
	mismatch := outer
	mismatch.TBS = asn1.RawValue{FullBytes: innerChanged}
	mismatch.Signature = asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}
	require.ErrorContains(t, CheckCertificateSignature(rebuild(mismatch), pub), "differs from the one in the tbsCertificate")
}

func TestCompositeSubjectKeyID(t *testing.T) {
	vectors := loadCompositeVectors(t)
	pub := vectorPublicKey(t, vectors, compositeFixtures[0])
	id, err := SubjectKeyID(pub)
	require.NoError(t, err)
	sum := sha1.Sum(decodeB64(t, vectors.find(t, compositeFixtures[0].tcID).PK))
	require.Equal(t, sum[:], id)
}

func mustParseCert(t *testing.T, b64 string) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(decodeB64(t, b64))
	require.NoError(t, err)
	return cert
}

func vectorPublicKey(t *testing.T, vectors compositeVectorFile, fx compositeFixture) *PublicKey {
	t.Helper()
	pub, err := ParsePublicKey(fixtureAlgorithm(t, fx), decodeB64(t, vectors.find(t, fx.tcID).PK))
	require.NoError(t, err)
	return pub
}

func flipByte(b []byte, i int) []byte {
	out := append([]byte{}, b...)
	out[i] ^= 0x01
	return out
}

func digest(t *testing.T, h crypto.Hash, message []byte) []byte {
	t.Helper()
	switch h {
	case crypto.SHA256:
		sum := sha256.Sum256(message)
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(message)
		return sum[:]
	}
	t.Fatalf("unexpected hash %s", h)
	return nil
}

func mldsaParameters(t *testing.T, level int) mldsa.Parameters {
	t.Helper()
	switch level {
	case 44:
		return mldsa.MLDSA44()
	case 65:
		return mldsa.MLDSA65()
	case 87:
		return mldsa.MLDSA87()
	}
	t.Fatalf("unexpected MLDSA level %d", level)
	return mldsa.Parameters{}
}
