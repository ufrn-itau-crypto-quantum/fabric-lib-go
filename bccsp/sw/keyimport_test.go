/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	mocks2 "github.com/hyperledger/fabric-lib-go/bccsp/mocks"
	"github.com/hyperledger/fabric-lib-go/bccsp/sw/mocks"
	"github.com/stretchr/testify/require"
)

func TestKeyImport(t *testing.T) {
	t.Parallel()

	expectedRaw := []byte{1, 2, 3}
	expectedOpts := &mocks2.KeyDerivOpts{EphemeralValue: true}
	expectetValue := &mocks2.MockKey{BytesValue: []byte{1, 2, 3, 4, 5}}
	expectedErr := errors.New("Expected Error")

	keyImporters := make(map[reflect.Type]KeyImporter)
	keyImporters[reflect.TypeOf(&mocks2.KeyDerivOpts{})] = &mocks.KeyImporter{
		RawArg:  expectedRaw,
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     expectedErr,
	}
	csp := CSP{KeyImporters: keyImporters}
	value, err := csp.KeyImport(expectedRaw, expectedOpts)
	require.Nil(t, value)
	require.Contains(t, err.Error(), expectedErr.Error())

	keyImporters = make(map[reflect.Type]KeyImporter)
	keyImporters[reflect.TypeOf(&mocks2.KeyDerivOpts{})] = &mocks.KeyImporter{
		RawArg:  expectedRaw,
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     nil,
	}
	csp = CSP{KeyImporters: keyImporters}
	value, err = csp.KeyImport(expectedRaw, expectedOpts)
	require.Equal(t, expectetValue, value)
	require.Nil(t, err)
}

func TestAES256ImportKeyOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := aes256ImportKeyOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid Key Length [")
}

func TestHMACImportKeyOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := hmacImportKeyOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. It must not be nil.")
}

func TestECDSAPKIXPublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := ecdsaPKIXPublicKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed converting PKIX to ECDSA public key [")

	k, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	raw, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	_, err = ki.KeyImport(raw, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed casting to ECDSA public key. Invalid raw material.")
}

func TestECDSAPrivateKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := ecdsaPrivateKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed converting PKIX to ECDSA public key")

	k, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	raw := x509.MarshalPKCS1PrivateKey(k)
	_, err = ki.KeyImport(raw, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed casting to ECDSA private key. Invalid raw material.")
}

func TestED25519PrivateKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := ed25519PrivateKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed converting PKIX to ED25519 public key")

	k, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	raw := x509.MarshalPKCS1PrivateKey(k)
	_, err = ki.KeyImport(raw, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed casting to ED25519 private key. Invalid raw material.")
}

func TestECDSAGoPublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := ecdsaGoPublicKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected *ecdsa.PublicKey.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected *ecdsa.PublicKey.")
}

func TestED25519GoPublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := ed25519GoPublicKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected *ed25519.PublicKey.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected *ed25519.PublicKey.")
}

func TestX509PublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := x509PublicKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected *x509.Certificate.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected *x509.Certificate.")

	cert := &x509.Certificate{}
	cert.PublicKey = "Hello world"
	_, err = ki.KeyImport(cert, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Certificate's public key type not recognized. Supported keys: [ECDSA, ED25519, ML-DSA, RSA]")
}

func TestX509RSAKeyImport(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "key generation failed")

	cert := &x509.Certificate{PublicKey: pk.Public()}
	ki := x509PublicKeyImportOptsKeyImporter{}
	key, err := ki.KeyImport(cert, nil)
	require.NoError(t, err, "key import failed")
	require.NotNil(t, key, "key must not be nil")
	require.Equal(t, &rsaPublicKey{pubKey: &pk.PublicKey}, key)
}

func TestMLDSAPrivateKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := &mldsaPrivateKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &bccsp.MLDSAPrivateKeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &bccsp.MLDSAPrivateKeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &bccsp.MLDSAPrivateKeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &bccsp.MLDSAPrivateKeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed converting PKCS8 to ML-DSA private key")

	// A well-formed DER of a different algorithm must be rejected on the cast.
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaDER, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	require.NoError(t, err)
	_, err = ki.KeyImport(ecdsaDER, &bccsp.MLDSAPrivateKeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed casting to ML-DSA private key")

	// The happy path.
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(mldsaKey)
	require.NoError(t, err)
	k, err := ki.KeyImport(der, &bccsp.MLDSAPrivateKeyImportOpts{})
	require.NoError(t, err)
	require.True(t, k.Private())
}

func TestMLDSAPKIXPublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := &mldsaPKIXPublicKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &bccsp.MLDSAPKIXPublicKeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &bccsp.MLDSAPKIXPublicKeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &bccsp.MLDSAPKIXPublicKeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed converting PKIX to ML-DSA public key")

	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(mldsaKey.PublicKey())
	require.NoError(t, err)
	k, err := ki.KeyImport(der, &bccsp.MLDSAPKIXPublicKeyImportOpts{})
	require.NoError(t, err)
	require.False(t, k.Private())
}

func TestMLDSAGoPublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := &mldsaGoPublicKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &bccsp.MLDSAGoPublicKeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected *mldsa.PublicKey.")

	_, err = ki.KeyImport(nil, &bccsp.MLDSAGoPublicKeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected *mldsa.PublicKey.")

	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	k, err := ki.KeyImport(mldsaKey.PublicKey(), &bccsp.MLDSAGoPublicKeyImportOpts{})
	require.NoError(t, err)
	require.False(t, k.Private())
}
