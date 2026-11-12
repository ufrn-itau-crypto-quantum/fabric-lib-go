/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pkixext_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/stretchr/testify/require"
)

type certificateOuter struct {
	TBS                asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Signature          asn1.BitString
}

var testSerial int64

// marshalSPKI returns nil for a key that crypto/x509 can encode itself.
func marshalSPKI(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	var der []byte
	var err error
	switch pk := pub.(type) {
	case *composite.PublicKey:
		der, err = composite.MarshalPKIXPublicKey(pk)
	case *slhdsa.PublicKey:
		der, err = slhdsa.MarshalPKIXPublicKey(pk)
	default:
		return nil
	}
	require.NoError(t, err)
	return der
}

// rewriteFields replaces the elements of a DER SEQUENCE given by index.
func rewriteFields(t *testing.T, seqDER []byte, replace map[int][]byte) []byte {
	t.Helper()
	var seq asn1.RawValue
	_, err := asn1.Unmarshal(seqDER, &seq)
	require.NoError(t, err)
	var content []byte
	for i, rest := 0, seq.Bytes; len(rest) > 0; i++ {
		var field asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &field)
		require.NoError(t, err)
		if r, ok := replace[i]; ok {
			content = append(content, r...)
		} else {
			content = append(content, field.FullBytes...)
		}
	}
	out, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
	require.NoError(t, err)
	return out
}

// issueCert issues tpl for subject, signed by signer on behalf of parent (nil for self-signed).
// crypto/x509 builds the TBS with a throwaway ECDSA key; the SPKI, the signature algorithm and the
// signature are then replaced when the subject or the signer is external.
func issueCert(t *testing.T, tpl, parent *x509.Certificate, subject crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	testSerial++
	tpl.SerialNumber = big.NewInt(testSerial)
	tpl.NotBefore = time.Now().Add(-time.Hour)
	tpl.NotAfter = time.Now().Add(time.Hour)
	if parent == nil {
		parent = tpl
	}
	throwaway := ecdsaKey(t)
	spki := marshalSPKI(t, subject)
	sigAlg, _ := pkixext.AlgorithmIdentifier(signer.Public())

	goSubject, goSigner := subject, signer
	if spki != nil {
		goSubject = throwaway.Public()
	}
	if sigAlg != nil {
		goSigner = throwaway
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, goSubject, goSigner)
	require.NoError(t, err)
	if spki == nil && sigAlg == nil {
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert
	}

	var outer certificateOuter
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)
	replace := map[int][]byte{}
	if sigAlg != nil {
		replace[2] = sigAlg
	}
	if spki != nil {
		replace[6] = spki
	}
	tbs := rewriteFields(t, outer.TBS.FullBytes, replace)
	var signature []byte
	if sigAlg != nil {
		signature, err = signer.Sign(rand.Reader, tbs, nil)
		outer.SignatureAlgorithm = asn1.RawValue{FullBytes: sigAlg}
	} else {
		sum := sha256.Sum256(tbs)
		signature, err = signer.Sign(rand.Reader, sum[:], crypto.SHA256)
	}
	require.NoError(t, err)
	outer.TBS = asn1.RawValue{FullBytes: tbs}
	outer.Signature = asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}
	der, err = asn1.Marshal(outer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// issueCRL has crypto/x509 build a CRL with a throwaway key, then replaces the algorithm and the
// signature with those of the external signer.
func issueCRL(t *testing.T, issuer *x509.Certificate, signer crypto.Signer, revoked ...*big.Int) *pkix.CertificateList {
	t.Helper()
	var list []pkix.RevokedCertificate
	for _, serial := range revoked {
		list = append(list, pkix.RevokedCertificate{SerialNumber: serial, RevocationTime: time.Now()})
	}
	//nolint:staticcheck
	der, err := issuer.CreateCRL(rand.Reader, ecdsaKey(t), list, time.Now(), time.Now().Add(time.Hour))
	require.NoError(t, err)
	var outer certificateOuter
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)

	algID, err := pkixext.AlgorithmIdentifier(signer.Public())
	require.NoError(t, err)
	tbs := rewriteFields(t, outer.TBS.FullBytes, map[int][]byte{1: algID})
	signature, err := signer.Sign(rand.Reader, tbs, nil)
	require.NoError(t, err)
	der, err = asn1.Marshal(certificateOuter{
		TBS:                asn1.RawValue{FullBytes: tbs},
		SignatureAlgorithm: asn1.RawValue{FullBytes: algID},
		Signature:          asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)},
	})
	require.NoError(t, err)
	//nolint:staticcheck
	crl, err := x509.ParseCRL(der)
	require.NoError(t, err)
	return crl
}

func caTemplate(name string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true, MaxPathLen: -1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte(name),
	}
}

func leafTemplate(name string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{CommonName: name}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte(name),
	}
}

func ecdsaKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func slhdsaKey(t *testing.T, ps slhdsa.ParameterSet) *slhdsa.PrivateKey {
	t.Helper()
	key, err := slhdsa.GenerateKey(ps)
	require.NoError(t, err)
	return key
}

func compositeKey(t *testing.T, level int) *composite.PrivateKey {
	t.Helper()
	alg, err := composite.AlgorithmForLevel(level)
	require.NoError(t, err)
	key, err := composite.GenerateKey(alg)
	require.NoError(t, err)
	return key
}

func verifyOpts(roots []*x509.Certificate, intermediates ...*x509.Certificate) pkixext.VerifyOptions {
	return pkixext.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
}

func TestRegistry(t *testing.T) {
	for _, ps := range slhdsa.ParameterSets() {
		s, ok := pkixext.SchemeByOID(ps.OID)
		require.True(t, ok, ps.Name)
		require.Equal(t, "SLH-DSA", s.Name())
	}
	s, ok := pkixext.SchemeByOID(composite.OIDMLDSA44ECDSAP256SHA256)
	require.True(t, ok)
	require.Equal(t, "composite", s.Name())

	_, ok = pkixext.SchemeByOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 35})
	require.False(t, ok)

	require.Panics(t, func() { pkixext.Register(duplicateScheme{s}) })
}

// duplicateScheme reuses the OIDs of an already registered scheme.
type duplicateScheme struct{ pkixext.Scheme }

func (duplicateScheme) Name() string { return "duplicate" }

func TestKeysAndIdentifiers(t *testing.T) {
	sk := slhdsaKey(t, slhdsa.SHA2_128f)
	spki := marshalSPKI(t, sk.PublicKey())
	require.True(t, pkixext.IsExternalPublicKey(spki))
	pub, err := pkixext.ParsePKIXPublicKey(spki)
	require.NoError(t, err)
	require.True(t, sk.PublicKey().Equal(pub))

	algID, err := pkixext.AlgorithmIdentifier(pub)
	require.NoError(t, err)
	want, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: slhdsa.SHA2_128f.OID})
	require.NoError(t, err)
	require.Equal(t, want, algID)
	_, err = pkixext.SubjectKeyID(pub)
	require.NoError(t, err)

	ec := ecdsaKey(t)
	ecSPKI, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	require.NoError(t, err)
	require.False(t, pkixext.IsExternalPublicKey(ecSPKI))
	_, err = pkixext.ParsePKIXPublicKey(ecSPKI)
	require.ErrorIs(t, err, pkixext.ErrNotExternal)
	_, err = pkixext.AlgorithmIdentifier(&ec.PublicKey)
	require.Error(t, err)
}

func TestRFC9909CertificateSKI(t *testing.T) {
	raw, err := os.ReadFile("../slhdsa/testdata/rfc9909/certificate.pem")
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	require.True(t, pkixext.IsSignedWithExternal(cert))
	pub, err := pkixext.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	require.NoError(t, pkixext.CheckCertificateSignature(cert, pub))
	ski, err := pkixext.SubjectKeyID(pub)
	require.NoError(t, err)
	require.Equal(t, cert.SubjectKeyId, ski)
}

func TestSLHDSAChain(t *testing.T) {
	rootKey := slhdsaKey(t, slhdsa.SHA2_128f)
	root := issueCert(t, caTemplate("root"), nil, rootKey.PublicKey(), rootKey)
	interKey := slhdsaKey(t, slhdsa.SHA2_128f)
	inter := issueCert(t, caTemplate("inter"), root, interKey.PublicKey(), rootKey)
	leafKey := slhdsaKey(t, slhdsa.SHA2_128f)
	leaf := issueCert(t, leafTemplate("leaf"), inter, leafKey.PublicKey(), interKey)
	ecLeaf := issueCert(t, leafTemplate("ec-leaf"), inter, ecdsaKey(t).Public(), interKey)

	require.True(t, pkixext.IsSignedWithExternal(leaf))
	require.Nil(t, leaf.PublicKey)
	require.NoError(t, pkixext.CheckCertificateSignature(root, rootKey.PublicKey()))
	require.NoError(t, pkixext.CheckCertificateSignature(leaf, interKey.PublicKey()))
	require.Error(t, pkixext.CheckCertificateSignature(leaf, rootKey.PublicKey()))

	for _, cert := range []*x509.Certificate{leaf, ecLeaf} {
		chains, err := pkixext.VerifyChain(cert, verifyOpts([]*x509.Certificate{root}, inter))
		require.NoError(t, err)
		require.Len(t, chains, 1)
		require.Equal(t, []*x509.Certificate{cert, inter, root}, chains[0])
	}

	_, err := pkixext.VerifyChain(leaf, verifyOpts([]*x509.Certificate{root}))
	require.ErrorContains(t, err, "unknown authority")
}

func TestSLHDSACRL(t *testing.T) {
	rootKey := slhdsaKey(t, slhdsa.SHA2_128f)
	root := issueCert(t, caTemplate("root"), nil, rootKey.PublicKey(), rootKey)
	crl := issueCRL(t, root, rootKey, big.NewInt(42))

	require.True(t, pkixext.IsCRLSignedWithExternal(crl))
	require.NoError(t, pkixext.CheckCRLSignature(crl, rootKey.PublicKey()))
	require.Error(t, root.CheckCRLSignature(crl))
	require.Equal(t, big.NewInt(42), crl.TBSCertList.RevokedCertificates[0].SerialNumber)

	require.Error(t, pkixext.CheckCRLSignature(crl, slhdsaKey(t, slhdsa.SHA2_128f).PublicKey()))
	require.ErrorContains(t, pkixext.CheckCRLSignature(crl, slhdsaKey(t, slhdsa.SHA2_192f).PublicKey()), "not the one of the issuer key")
	require.ErrorContains(t, pkixext.CheckCRLSignature(crl, compositeKey(t, 44).PublicKey()), "not the one of the issuer key")

	withNull := *crl
	withNull.SignatureAlgorithm.Parameters = asn1.NullRawValue
	require.ErrorContains(t, pkixext.CheckCRLSignature(&withNull, rootKey.PublicKey()), "not the one of the issuer key")
	tampered := *crl
	tampered.TBSCertList.Raw = append([]byte(nil), crl.TBSCertList.Raw...)
	tampered.TBSCertList.Raw[len(tampered.TBSCertList.Raw)-1] ^= 1
	require.Error(t, pkixext.CheckCRLSignature(&tampered, rootKey.PublicKey()))
}

func TestMixedChains(t *testing.T) {
	t.Run("SLH-DSA root, composite intermediate", func(t *testing.T) {
		rootKey := slhdsaKey(t, slhdsa.SHA2_128f)
		root := issueCert(t, caTemplate("root"), nil, rootKey.PublicKey(), rootKey)
		interKey := compositeKey(t, 44)
		inter := issueCert(t, caTemplate("inter"), root, interKey.PublicKey(), rootKey)
		leaf := issueCert(t, leafTemplate("leaf"), inter, ecdsaKey(t).Public(), interKey)

		chains, err := pkixext.VerifyChain(leaf, verifyOpts([]*x509.Certificate{root}, inter))
		require.NoError(t, err)
		require.Equal(t, []*x509.Certificate{leaf, inter, root}, chains[0])
		require.True(t, composite.IsSignedWithComposite(leaf))
		require.False(t, composite.IsSignedWithComposite(inter))
	})

	t.Run("composite root, SLH-DSA intermediate", func(t *testing.T) {
		rootKey := compositeKey(t, 65)
		root := issueCert(t, caTemplate("root"), nil, rootKey.PublicKey(), rootKey)
		interKey := slhdsaKey(t, slhdsa.SHA2_128f)
		inter := issueCert(t, caTemplate("inter"), root, interKey.PublicKey(), rootKey)
		leaf := issueCert(t, leafTemplate("leaf"), inter, slhdsaKey(t, slhdsa.SHA2_128f).PublicKey(), interKey)

		chains, err := pkixext.VerifyChain(leaf, verifyOpts([]*x509.Certificate{root}, inter))
		require.NoError(t, err)
		require.Equal(t, []*x509.Certificate{leaf, inter, root}, chains[0])

		chains, err = composite.VerifyChain(leaf, verifyOpts([]*x509.Certificate{root}, inter))
		require.NoError(t, err)
		require.Len(t, chains, 1)
	})

	t.Run("classical root, SLH-DSA intermediate", func(t *testing.T) {
		rootKey := ecdsaKey(t)
		root := issueCert(t, caTemplate("root"), nil, rootKey.Public(), rootKey)
		interKey := slhdsaKey(t, slhdsa.SHA2_128f)
		inter := issueCert(t, caTemplate("inter"), root, interKey.PublicKey(), rootKey)
		leaf := issueCert(t, leafTemplate("leaf"), inter, ecdsaKey(t).Public(), interKey)

		_, err := pkixext.VerifyChain(leaf, verifyOpts([]*x509.Certificate{root}, inter))
		require.NoError(t, err)
	})
}

func TestChainRejectsSchemeMismatch(t *testing.T) {
	slhKey := slhdsaKey(t, slhdsa.SHA2_128f)
	compKey := compositeKey(t, 44)
	compRoot := issueCert(t, caTemplate("root"), nil, compKey.PublicKey(), compKey)
	slhRoot := issueCert(t, caTemplate("root"), nil, slhKey.PublicKey(), slhKey)

	issuerName := *compRoot
	issuerName.PublicKey = nil
	leaf := issueCert(t, leafTemplate("leaf"), &issuerName, ecdsaKey(t).Public(), slhKey)
	_, err := pkixext.VerifyChain(leaf, verifyOpts([]*x509.Certificate{compRoot}))
	require.ErrorContains(t, err, "is not SLH-DSA")
	_, err = pkixext.VerifyChain(leaf, verifyOpts([]*x509.Certificate{slhRoot}))
	require.NoError(t, err)

	require.ErrorContains(t, pkixext.CheckCertificateSignature(leaf, compKey.PublicKey()), "but the issuer key is")
	require.ErrorContains(t, pkixext.CheckCertificateSignature(leaf, slhdsaKey(t, slhdsa.SHA2_128s).PublicKey()), "but the issuer key is")
}

func TestCertificateRejectsInnerAlgorithmMismatch(t *testing.T) {
	key := slhdsaKey(t, slhdsa.SHA2_128f)
	cert := issueCert(t, caTemplate("root"), nil, key.PublicKey(), key)
	var outer certificateOuter
	_, err := asn1.Unmarshal(cert.Raw, &outer)
	require.NoError(t, err)

	other, err := slhdsa.AlgorithmIdentifier(slhdsa.SHA2_128s)
	require.NoError(t, err)
	tbs := rewriteFields(t, outer.TBS.FullBytes, map[int][]byte{2: other})
	sig, err := key.Sign(rand.Reader, tbs, nil)
	require.NoError(t, err)
	outer.TBS = asn1.RawValue{FullBytes: tbs}
	outer.Signature = asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}
	der, err := asn1.Marshal(outer)
	require.NoError(t, err)

	require.ErrorContains(t, pkixext.CheckCertificateSignature(&x509.Certificate{Raw: der}, key.PublicKey()),
		"differs from the one in the tbsCertificate")

	withNull, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: slhdsa.SHA2_128f.OID, Parameters: asn1.NullRawValue})
	require.NoError(t, err)
	_, err = asn1.Unmarshal(cert.Raw, &outer)
	require.NoError(t, err)
	tbs = rewriteFields(t, outer.TBS.FullBytes, map[int][]byte{2: withNull})
	sig, err = key.Sign(rand.Reader, tbs, nil)
	require.NoError(t, err)
	outer.TBS = asn1.RawValue{FullBytes: tbs}
	outer.SignatureAlgorithm = asn1.RawValue{FullBytes: withNull}
	outer.Signature = asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}
	der, err = asn1.Marshal(outer)
	require.NoError(t, err)
	require.ErrorContains(t, pkixext.CheckCertificateSignature(&x509.Certificate{Raw: der}, key.PublicKey()),
		"but the issuer key is")
}
