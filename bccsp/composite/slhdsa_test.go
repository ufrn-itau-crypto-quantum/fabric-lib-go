/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/stretchr/testify/require"
)

// updateSLHDSAVectors regenerates the fixed vectors; the origin is in
// testdata/composite-slhdsa/SOURCE.
var updateSLHDSAVectors = flag.Bool("update-composite-slhdsa", false, "regenerate testdata/composite-slhdsa/vectors.json")

const compositeSLHDSAVectorsPath = "testdata/composite-slhdsa/vectors.json"

type slhdsaVectorFile struct {
	M     string         `json:"m"`
	Ctx   string         `json:"ctx"`
	Tests []slhdsaVector `json:"tests"`
}

type slhdsaVector struct {
	Label        string `json:"label"`
	OID          string `json:"oid"`
	PK           string `json:"pk"`
	SKPKCS8      string `json:"sk_pkcs8"`
	S            string `json:"s"`
	SWithContext string `json:"sWithContext"`
}

// slhdsaFixture holds the values the experimental pairs are expected to have. The ECDSA public key
// is uncompressed: 0x04 and two coordinates.
var slhdsaFixtures = []struct {
	params    slhdsa.ParameterSet
	oid       string
	label     string
	hash      crypto.Hash
	tradHash  crypto.Hash
	ecPubSize int
}{
	{slhdsa.SHA2_128s, "1.3.6.1.4.1.32473.1.1", "COMPSIG-SLHDSA-SHA2-128S-ECDSA-P256-SHA256", crypto.SHA256, crypto.SHA256, 65},
	{slhdsa.SHA2_128f, "1.3.6.1.4.1.32473.1.2", "COMPSIG-SLHDSA-SHA2-128F-ECDSA-P256-SHA256", crypto.SHA256, crypto.SHA256, 65},
	{slhdsa.SHA2_192s, "1.3.6.1.4.1.32473.1.3", "COMPSIG-SLHDSA-SHA2-192S-ECDSA-P384-SHA512", crypto.SHA512, crypto.SHA384, 97},
	{slhdsa.SHA2_192f, "1.3.6.1.4.1.32473.1.4", "COMPSIG-SLHDSA-SHA2-192F-ECDSA-P384-SHA512", crypto.SHA512, crypto.SHA384, 97},
	{slhdsa.SHA2_256s, "1.3.6.1.4.1.32473.1.5", "COMPSIG-SLHDSA-SHA2-256S-ECDSA-P384-SHA512", crypto.SHA512, crypto.SHA384, 97},
	{slhdsa.SHA2_256f, "1.3.6.1.4.1.32473.1.6", "COMPSIG-SLHDSA-SHA2-256F-ECDSA-P384-SHA512", crypto.SHA512, crypto.SHA384, 97},
}

func slhdsaPair(t *testing.T, ps slhdsa.ParameterSet) Algorithm {
	t.Helper()
	alg, err := AlgorithmForSLHDSA(ps)
	require.NoError(t, err)
	return alg
}

func TestCompositeSLHDSAAlgorithmTable(t *testing.T) {
	for _, fx := range slhdsaFixtures {
		alg := slhdsaPair(t, fx.params)
		require.Equal(t, fx.oid, alg.OID.String())
		require.Equal(t, fx.label, alg.Label)
		require.Equal(t, fx.hash, alg.Hash)
		require.Equal(t, fx.tradHash, alg.TraditionalHash)
		require.Zero(t, alg.MLDSALevel)
		require.Equal(t, fx.params.Name, alg.PQ.Name())
		require.Equal(t, "SLH-DSA", alg.PQ.Family())

		byOID, err := AlgorithmByOID(alg.OID)
		require.NoError(t, err)
		require.Equal(t, fx.label, byOID.Label)
	}

	_, err := AlgorithmForSLHDSA(slhdsa.SHAKE_128s)
	require.Error(t, err)
	_, err = AlgorithmForLevel(0)
	require.Error(t, err)
}

func TestCompositeSLHDSARoundTrip(t *testing.T) {
	m := []byte("message")
	ctx := []byte("context")
	for _, fx := range slhdsaFixtures {
		t.Run(fx.label, func(t *testing.T) {
			t.Parallel()
			alg := slhdsaPair(t, fx.params)
			sk, err := GenerateKey(alg)
			require.NoError(t, err)
			require.Nil(t, sk.MLDSA)
			require.NotNil(t, sk.SLHDSA)

			pk, err := sk.PublicKey().Bytes()
			require.NoError(t, err)
			require.Len(t, pk, fx.params.PublicKeySize()+fx.ecPubSize)
			parsedPK, err := ParsePublicKey(alg, pk)
			require.NoError(t, err)
			require.True(t, parsedPK.Equal(sk.PublicKey()))

			raw, err := sk.Bytes()
			require.NoError(t, err)
			parsedSK, err := ParsePrivateKey(alg, raw)
			require.NoError(t, err)
			require.True(t, parsedSK.PublicKey().Equal(sk.PublicKey()))

			der, err := MarshalPKCS8PrivateKey(sk)
			require.NoError(t, err)
			fromPKCS8, err := ParsePKCS8PrivateKey(der)
			require.NoError(t, err)
			require.True(t, fromPKCS8.PublicKey().Equal(sk.PublicKey()))
			spki, err := MarshalPKIXPublicKey(sk.PublicKey())
			require.NoError(t, err)
			fromSPKI, err := ParsePKIXPublicKey(spki)
			require.NoError(t, err)
			require.True(t, fromSPKI.Equal(sk.PublicKey()))

			sig, err := parsedSK.Sign(rand.Reader, m, &SignerOpts{Context: ctx})
			require.NoError(t, err)
			pqSig, _, err := DeserializeSignatureValue(alg, sig)
			require.NoError(t, err)
			require.Len(t, pqSig, fx.params.SignatureSize())
			require.NoError(t, Verify(fromSPKI, m, sig, ctx))
			require.Error(t, Verify(fromSPKI, m, sig, nil))
			require.Error(t, Verify(fromSPKI, []byte("other"), sig, ctx))
		})
	}
}

func TestCompositeSLHDSARequiresBothComponents(t *testing.T) {
	m := []byte("message")
	alg := slhdsaPair(t, slhdsa.SHA2_128f)
	a, err := GenerateKey(alg)
	require.NoError(t, err)
	b, err := GenerateKey(alg)
	require.NoError(t, err)
	sig, err := a.Sign(nil, m, nil)
	require.NoError(t, err)

	mixedPQ := &PublicKey{Algorithm: alg, SLHDSA: b.SLHDSA.PublicKey(), Traditional: &a.Traditional.PublicKey}
	mixedEC := &PublicKey{Algorithm: alg, SLHDSA: a.SLHDSA.PublicKey(), Traditional: &b.Traditional.PublicKey}
	require.ErrorContains(t, Verify(mixedPQ, m, sig, nil), "SLH-DSA component")
	require.ErrorContains(t, Verify(mixedEC, m, sig, nil), "ECDSA component")
	require.False(t, a.PublicKey().Equal(mixedPQ))
	require.False(t, a.PublicKey().Equal(mixedEC))

	other := a.PublicKey()
	other.Algorithm.Label = "COMPSIG-SLHDSA-SHA2-128S-ECDSA-P256-SHA256"
	require.Error(t, Verify(other, m, sig, nil))
}

func TestCompositeSLHDSARejectsOtherFamilies(t *testing.T) {
	slh := slhdsaPair(t, slhdsa.SHA2_128f)
	ml, err := AlgorithmForLevel(44)
	require.NoError(t, err)
	slhKey, err := GenerateKey(slh)
	require.NoError(t, err)
	mlKey, err := GenerateKey(ml)
	require.NoError(t, err)

	pk, err := slhKey.PublicKey().Bytes()
	require.NoError(t, err)
	_, err = ParsePublicKey(ml, pk)
	require.Error(t, err)
	_, err = ParsePublicKey(slhdsaPair(t, slhdsa.SHA2_128s), pk)
	require.NoError(t, err, "128s and 128f share sizes; only the signature tells them apart")

	sk, err := mlKey.Bytes()
	require.NoError(t, err)
	_, err = ParsePrivateKey(slh, sk)
	require.Error(t, err)

	wrong := &PublicKey{Algorithm: slh, MLDSA: mlKey.MLDSA.PublicKey(), Traditional: &slhKey.Traditional.PublicKey}
	_, err = wrong.Bytes()
	require.Error(t, err)
	sig, err := slhKey.Sign(nil, []byte("m"), nil)
	require.NoError(t, err)
	require.Error(t, Verify(wrong, []byte("m"), sig, nil))

	_, err = slhKey.Sign(nil, []byte("m"), crypto.SHA256)
	require.ErrorContains(t, err, "Composite SLH-DSA signs the whole message")
}

func TestCompositeSLHDSACertificateChain(t *testing.T) {
	rootKey, err := GenerateKey(slhdsaPair(t, slhdsa.SHA2_128f))
	require.NoError(t, err)
	root := issueTestCert(t, caTemplate("root"), nil, rootKey.PublicKey(), rootKey)
	leaf := issueTestCert(t, leafTemplate("leaf"), root, testECDSAKey(t).Public(), rootKey)

	require.True(t, IsSignedWithComposite(leaf))
	require.NoError(t, CheckCertificateSignature(leaf, rootKey.PublicKey()))
	chains, err := VerifyChain(leaf, VerifyOptions{Roots: []*x509.Certificate{root}, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	require.NoError(t, err)
	require.Equal(t, []*x509.Certificate{leaf, root}, chains[0])

	crl := issueTestCRL(t, root, rootKey, big.NewInt(7))
	require.True(t, IsCRLSignedWithComposite(crl))
	require.NoError(t, CheckCRLSignature(crl, rootKey.PublicKey()))
}

func TestCompositeSLHDSAAgainstFixedVectors(t *testing.T) {
	if *updateSLHDSAVectors {
		writeSLHDSAVectors(t)
	}
	raw, err := os.ReadFile(compositeSLHDSAVectorsPath)
	require.NoError(t, err)
	var file slhdsaVectorFile
	require.NoError(t, json.Unmarshal(raw, &file))
	require.Len(t, file.Tests, len(slhdsaFixtures))
	m, ctx := decodeB64(t, file.M), decodeB64(t, file.Ctx)

	for i, fx := range slhdsaFixtures {
		v := file.Tests[i]
		t.Run(fx.label, func(t *testing.T) {
			require.Equal(t, fx.label, v.Label)
			require.Equal(t, fx.oid, v.OID)

			skDER := decodeB64(t, v.SKPKCS8)
			sk, err := ParsePKCS8PrivateKey(skDER)
			require.NoError(t, err)
			again, err := MarshalPKCS8PrivateKey(sk)
			require.NoError(t, err)
			require.Equal(t, skDER, again)

			spki := decodeB64(t, v.PK)
			pub, err := ParsePKIXPublicKey(spki)
			require.NoError(t, err)
			require.True(t, sk.PublicKey().Equal(pub))
			again, err = MarshalPKIXPublicKey(pub)
			require.NoError(t, err)
			require.Equal(t, spki, again)

			require.NoError(t, Verify(pub, m, decodeB64(t, v.S), nil))
			require.NoError(t, Verify(pub, m, decodeB64(t, v.SWithContext), ctx))
			require.Error(t, Verify(pub, m, decodeB64(t, v.SWithContext), nil))
		})
	}
}

// writeSLHDSAVectors generates a key per pair and signs the fixed message with and without the
// fixed context. Signatures are randomized, so a regeneration changes every value.
func writeSLHDSAVectors(t *testing.T) {
	t.Helper()
	m := []byte("Composite SLH-DSA fixed test vector")
	ctx := []byte("fabric")
	b64 := base64.StdEncoding.EncodeToString
	file := slhdsaVectorFile{M: b64(m), Ctx: b64(ctx)}
	for _, fx := range slhdsaFixtures {
		alg := slhdsaPair(t, fx.params)
		sk, err := GenerateKey(alg)
		require.NoError(t, err)
		skDER, err := MarshalPKCS8PrivateKey(sk)
		require.NoError(t, err)
		spki, err := MarshalPKIXPublicKey(sk.PublicKey())
		require.NoError(t, err)
		s, err := sk.Sign(nil, m, nil)
		require.NoError(t, err)
		sCtx, err := sk.Sign(nil, m, &SignerOpts{Context: ctx})
		require.NoError(t, err)
		file.Tests = append(file.Tests, slhdsaVector{
			Label: alg.Label, OID: alg.OID.String(), PK: b64(spki), SKPKCS8: b64(skDER), S: b64(s), SWithContext: b64(sCtx),
		})
	}
	out, err := json.MarshalIndent(file, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(compositeSLHDSAVectorsPath), 0o755))
	require.NoError(t, os.WriteFile(compositeSLHDSAVectorsPath, append(out, '\n'), 0o644))
}

func TestCompositeSLHDSAOIDsAreExperimental(t *testing.T) {
	for _, fx := range slhdsaFixtures {
		oid := slhdsaPair(t, fx.params).OID
		require.True(t, len(oid) > len(oidExperimentalArc) && asn1.ObjectIdentifier(oid[:len(oidExperimentalArc)]).Equal(oidExperimentalArc))
		der, err := asn1.Marshal(oid)
		require.NoError(t, err)
		var back asn1.ObjectIdentifier
		_, err = asn1.Unmarshal(der, &back)
		require.NoError(t, err)
		require.True(t, oid.Equal(back))
	}
}
