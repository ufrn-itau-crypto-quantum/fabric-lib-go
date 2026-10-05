/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testSerial int64

// issueTestCert emite tpl com a chave pública subject, assinado por signer em nome de parent (nil para
// autoassinado). A chave e a assinatura podem ser composite ou ECDSA P-256. O TBS é montado com uma
// chave descartável, e o SPKI e a assinatura são trocados depois.
func issueTestCert(t *testing.T, tpl, parent *x509.Certificate, subject crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	testSerial++
	tpl.SerialNumber = big.NewInt(testSerial)
	if tpl.NotBefore.IsZero() {
		tpl.NotBefore = time.Now().Add(-time.Hour)
		tpl.NotAfter = time.Now().Add(time.Hour)
	}
	if parent == nil {
		parent = tpl
	}
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	goSubject := subject
	if _, ok := subject.(*PublicKey); ok {
		goSubject = throwaway.Public()
	}
	goSigner := signer
	if _, ok := signer.(*PrivateKey); ok {
		goSigner = throwaway
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, goSubject, goSigner)
	require.NoError(t, err)
	var outer certificateOuter
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)

	var spki, sigAlg []byte
	if pub, ok := subject.(*PublicKey); ok {
		spki, err = MarshalPKIXPublicKey(pub)
		require.NoError(t, err)
	}
	if key, ok := signer.(*PrivateKey); ok {
		sigAlg, err = AlgorithmIdentifier(key.PublicKey().Algorithm)
		require.NoError(t, err)
	}
	if spki == nil && sigAlg == nil {
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert
	}

	tbs := rewriteTestTBS(t, outer.TBS.FullBytes, sigAlg, spki)
	var signature []byte
	if key, ok := signer.(*PrivateKey); ok {
		signature, err = key.Sign(rand.Reader, tbs, nil)
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

// rewriteTestTBS troca os campos signature e subjectPublicKeyInfo do TBS quando não são nil
func rewriteTestTBS(t *testing.T, tbs, sigAlg, spki []byte) []byte {
	t.Helper()
	var seq asn1.RawValue
	_, err := asn1.Unmarshal(tbs, &seq)
	require.NoError(t, err)
	var fields [][]byte
	for rest := seq.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &field)
		require.NoError(t, err)
		fields = append(fields, field.FullBytes)
	}
	// version [0], serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
	if sigAlg != nil {
		fields[2] = sigAlg
	}
	if spki != nil {
		fields[6] = spki
	}
	var content []byte
	for _, field := range fields {
		content = append(content, field...)
	}
	out, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
	require.NoError(t, err)
	return out
}

// issueTestCRL gera com o CreateCRL do crypto/x509 uma CRL assinada por uma chave descartável em
// nome de issuer, e troca o algoritmo e a assinatura pelos de signer.
func issueTestCRL(t *testing.T, issuer *x509.Certificate, signer *PrivateKey, revoked ...*big.Int) *pkix.CertificateList {
	t.Helper()
	var list []pkix.RevokedCertificate
	for _, serial := range revoked {
		list = append(list, pkix.RevokedCertificate{SerialNumber: serial, RevocationTime: time.Now()})
	}
	//nolint:staticcheck
	der, err := issuer.CreateCRL(rand.Reader, testECDSAKey(t), list, time.Now(), time.Now().Add(time.Hour))
	require.NoError(t, err)
	var outer certificateOuter
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)

	var seq asn1.RawValue
	_, err = asn1.Unmarshal(outer.TBS.FullBytes, &seq)
	require.NoError(t, err)
	var fields [][]byte
	for rest := seq.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &field)
		require.NoError(t, err)
		fields = append(fields, field.FullBytes)
	}
	// version, signature, issuer, thisUpdate, nextUpdate, revokedCertificates, crlExtensions
	algID, err := AlgorithmIdentifier(signer.PublicKey().Algorithm)
	require.NoError(t, err)
	fields[1] = algID
	var content []byte
	for _, field := range fields {
		content = append(content, field...)
	}
	tbs, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
	require.NoError(t, err)
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

func testCompositeKey(t *testing.T, level int) *PrivateKey {
	t.Helper()
	alg, err := AlgorithmForLevel(level)
	require.NoError(t, err)
	key, err := GenerateKey(alg)
	require.NoError(t, err)
	return key
}

func testECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

type testPKI struct {
	rootKey  *PrivateKey
	root     *x509.Certificate
	interKey *PrivateKey
	inter    *x509.Certificate
	ecInter  *x509.Certificate
	ecKey    *ecdsa.PrivateKey
	leaf     *x509.Certificate // chave ECDSA, assinado pela intermediária composite
	ecLeaf   *x509.Certificate // chave composite, assinado em ECDSA pela intermediária ECDSA
}

// newTestPKI monta uma raiz composite com uma intermediária composite e outra ECDSA
func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	var p testPKI
	p.rootKey = testCompositeKey(t, 65)
	p.root = issueTestCert(t, caTemplate("root"), nil, p.rootKey.PublicKey(), p.rootKey)
	p.interKey = testCompositeKey(t, 44)
	p.inter = issueTestCert(t, caTemplate("inter"), p.root, p.interKey.PublicKey(), p.rootKey)
	p.ecKey = testECDSAKey(t)
	p.ecInter = issueTestCert(t, caTemplate("ec-inter"), p.root, p.ecKey.Public(), p.rootKey)
	p.leaf = issueTestCert(t, leafTemplate("leaf"), p.inter, testECDSAKey(t).Public(), p.interKey)
	p.ecLeaf = issueTestCert(t, leafTemplate("ec-leaf"), p.ecInter, testCompositeKey(t, 44).PublicKey(), p.ecKey)
	return p
}

func (p testPKI) opts() VerifyOptions {
	return VerifyOptions{
		Roots:         []*x509.Certificate{p.root},
		Intermediates: []*x509.Certificate{p.inter, p.ecInter},
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
}

func TestCompositeVerifyChainAgainstVectors(t *testing.T) {
	vectors := loadCompositeVectors(t)
	for _, fx := range compositeFixtures {
		t.Run(fx.tcID, func(t *testing.T) {
			cert := mustParseCert(t, vectors.find(t, fx.tcID).X5c)
			require.True(t, IsSignedWithComposite(cert))
			chains, err := VerifyChain(cert, VerifyOptions{
				Roots: []*x509.Certificate{cert}, CurrentTime: cert.NotBefore.Add(time.Minute),
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			require.NoError(t, err)
			require.Equal(t, [][]*x509.Certificate{{cert}}, chains)
		})
	}
}

func TestCompositeVerifyChain(t *testing.T) {
	p := newTestPKI(t)
	require.True(t, IsSignedWithComposite(p.leaf))
	require.False(t, IsSignedWithComposite(p.ecLeaf))

	chains, err := VerifyChain(p.leaf, p.opts())
	require.NoError(t, err)
	require.Equal(t, [][]*x509.Certificate{{p.leaf, p.inter, p.root}}, chains)

	chains, err = VerifyChain(p.ecLeaf, p.opts())
	require.NoError(t, err)
	require.Equal(t, [][]*x509.Certificate{{p.ecLeaf, p.ecInter, p.root}}, chains)

	roots := x509.NewCertPool()
	roots.AddCert(p.root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(p.inter)
	intermediates.AddCert(p.ecInter)
	_, err = p.leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	require.Error(t, err)
}

func TestCompositeCRLSignature(t *testing.T) {
	p := newTestPKI(t)
	crl := issueTestCRL(t, p.inter, p.interKey, p.leaf.SerialNumber)
	require.True(t, IsCRLSignedWithComposite(crl))
	require.NoError(t, CheckCRLSignature(crl, p.interKey.PublicKey()))
	require.Equal(t, p.leaf.SerialNumber, crl.TBSCertList.RevokedCertificates[0].SerialNumber)

	require.Error(t, p.inter.CheckCRLSignature(crl))

	other := testCompositeKey(t, 44)
	require.Error(t, CheckCRLSignature(crl, other.PublicKey()))

	require.ErrorContains(t, CheckCRLSignature(crl, p.rootKey.PublicKey()), "not the one of the issuer key")

	tampered := *crl
	tampered.TBSCertList.Raw = flipByte(crl.TBSCertList.Raw, len(crl.TBSCertList.Raw)-1)
	require.Error(t, CheckCRLSignature(&tampered, p.interKey.PublicKey()))

	withNull := *crl
	withNull.SignatureAlgorithm.Parameters = asn1.NullRawValue
	require.ErrorContains(t, CheckCRLSignature(&withNull, p.interKey.PublicKey()), "not the one of the issuer key")
	innerNull := *crl
	innerNull.TBSCertList.Signature.Parameters = asn1.NullRawValue
	require.ErrorContains(t, CheckCRLSignature(&innerNull, p.interKey.PublicKey()), "not the one of the issuer key")

	shortBits := *crl
	shortBits.SignatureValue.BitLength--
	require.ErrorContains(t, CheckCRLSignature(&shortBits, p.interKey.PublicKey()), "whole number of bytes")

	//nolint:staticcheck
	der, err := p.ecInter.CreateCRL(rand.Reader, p.ecKey, nil, time.Now(), time.Now().Add(time.Hour))
	require.NoError(t, err)
	//nolint:staticcheck
	classic, err := x509.ParseCRL(der)
	require.NoError(t, err)
	require.False(t, IsCRLSignedWithComposite(classic))
	require.False(t, IsCRLSignedWithComposite(nil))
}

func TestCompositeVerifyChainKeyUsage(t *testing.T) {
	p := newTestPKI(t)
	opts := p.opts()

	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	_, err := VerifyChain(p.leaf, opts)
	require.NoError(t, err)

	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	_, err = VerifyChain(p.leaf, opts)
	require.ErrorContains(t, err, "incompatible key usage")

	opts.KeyUsages = nil
	_, err = VerifyChain(p.leaf, opts)
	require.ErrorContains(t, err, "incompatible key usage")
}

func TestCompositeVerifyChainRejects(t *testing.T) {
	p := newTestPKI(t)

	t.Run("expired", func(t *testing.T) {
		opts := p.opts()
		opts.CurrentTime = p.leaf.NotAfter.Add(time.Minute)
		_, err := VerifyChain(p.leaf, opts)
		require.ErrorContains(t, err, "expired")
	})

	t.Run("missing intermediate", func(t *testing.T) {
		opts := p.opts()
		opts.Intermediates = []*x509.Certificate{p.ecInter}
		_, err := VerifyChain(p.leaf, opts)
		require.ErrorContains(t, err, "unknown authority")
	})

	t.Run("no roots", func(t *testing.T) {
		opts := p.opts()
		opts.Roots = nil
		_, err := VerifyChain(p.leaf, opts)
		require.Error(t, err)
	})

	t.Run("other root with the same name", func(t *testing.T) {
		otherKey := testCompositeKey(t, 65)
		other := issueTestCert(t, caTemplate("root"), nil, otherKey.PublicKey(), otherKey)
		opts := p.opts()
		opts.Roots = []*x509.Certificate{other}
		_, err := VerifyChain(p.leaf, opts)
		require.ErrorContains(t, err, "unknown authority")

		_, err = VerifyChain(other, p.opts())
		require.ErrorContains(t, err, "unknown authority")
	})

	tamper := func(t *testing.T, cert *x509.Certificate) *x509.Certificate {
		var outer certificateOuter
		_, err := asn1.Unmarshal(cert.Raw, &outer)
		require.NoError(t, err)
		outer.Signature.Bytes = flipByte(outer.Signature.Bytes, 10)
		der, err := asn1.Marshal(outer)
		require.NoError(t, err)
		tampered, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return tampered
	}

	t.Run("tampered signature", func(t *testing.T) {
		_, err := VerifyChain(tamper(t, p.leaf), p.opts())
		require.ErrorContains(t, err, "unknown authority")
	})

	t.Run("tampered classical signature", func(t *testing.T) {
		_, err := VerifyChain(tamper(t, p.ecLeaf), p.opts())
		require.ErrorContains(t, err, "unknown authority")
	})

	t.Run("issuer is not a CA", func(t *testing.T) {
		tpl := caTemplate("not-ca")
		tpl.IsCA = false
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
		key := testCompositeKey(t, 44)
		notCA := issueTestCert(t, tpl, p.root, key.PublicKey(), p.rootKey)
		leaf := issueTestCert(t, leafTemplate("leaf"), notCA, testECDSAKey(t).Public(), key)
		opts := p.opts()
		opts.Intermediates = []*x509.Certificate{notCA}
		_, err := VerifyChain(leaf, opts)
		require.ErrorContains(t, err, "is not a CA")
	})

	t.Run("issuer without CertSign", func(t *testing.T) {
		tpl := caTemplate("no-certsign")
		tpl.KeyUsage = x509.KeyUsageCRLSign
		key := testCompositeKey(t, 44)
		inter := issueTestCert(t, tpl, p.root, key.PublicKey(), p.rootKey)
		leaf := issueTestCert(t, leafTemplate("leaf"), inter, testECDSAKey(t).Public(), key)
		opts := p.opts()
		opts.Intermediates = []*x509.Certificate{inter}
		_, err := VerifyChain(leaf, opts)
		require.ErrorContains(t, err, "not allowed to sign certificates")
	})

	t.Run("path length", func(t *testing.T) {
		tpl := caTemplate("pathlen-zero")
		tpl.MaxPathLen = 0
		tpl.MaxPathLenZero = true
		key := testCompositeKey(t, 44)
		limited := issueTestCert(t, tpl, p.root, key.PublicKey(), p.rootKey)
		belowKey := testCompositeKey(t, 44)
		below := issueTestCert(t, caTemplate("below"), limited, belowKey.PublicKey(), key)
		leaf := issueTestCert(t, leafTemplate("leaf"), below, testECDSAKey(t).Public(), belowKey)
		opts := p.opts()
		opts.Intermediates = []*x509.Certificate{limited, below}
		_, err := VerifyChain(leaf, opts)
		require.ErrorContains(t, err, "at most 0 intermediate")

		direct := issueTestCert(t, leafTemplate("direct"), limited, testECDSAKey(t).Public(), key)
		_, err = VerifyChain(direct, opts)
		require.NoError(t, err)
	})

	t.Run("name constraints", func(t *testing.T) {
		tpl := caTemplate("constrained")
		tpl.PermittedDNSDomains = []string{"example.com"}
		key := testCompositeKey(t, 44)
		inter := issueTestCert(t, tpl, p.root, key.PublicKey(), p.rootKey)
		leaf := issueTestCert(t, leafTemplate("leaf"), inter, testECDSAKey(t).Public(), key)
		opts := p.opts()
		opts.Intermediates = []*x509.Certificate{inter}
		_, err := VerifyChain(leaf, opts)
		require.ErrorContains(t, err, "name constraints")
	})

	t.Run("unhandled critical extension", func(t *testing.T) {
		tpl := leafTemplate("critical")
		tpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}, Critical: true, Value: []byte{0x05, 0x00}}}
		leaf := issueTestCert(t, tpl, p.inter, testECDSAKey(t).Public(), p.interKey)
		_, err := VerifyChain(leaf, p.opts())
		require.ErrorContains(t, err, "unhandled critical extension")
	})

	t.Run("composite signature under a classical issuer key", func(t *testing.T) {
		issuerName := *p.ecInter
		issuerName.PublicKey = nil
		leaf := issueTestCert(t, leafTemplate("leaf"), &issuerName, testECDSAKey(t).Public(), p.rootKey)
		opts := p.opts()
		opts.Intermediates = []*x509.Certificate{p.ecInter}
		_, err := VerifyChain(leaf, opts)
		require.ErrorContains(t, err, "is not composite")
	})
}
