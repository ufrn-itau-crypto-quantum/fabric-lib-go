/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	bccspsigner "github.com/hyperledger/fabric-lib-go/bccsp/signer"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/stretchr/testify/require"
)

func TestCompositeSLHDSABCCSP(t *testing.T) {
	msg := []byte("message")
	for _, ps := range []slhdsa.ParameterSet{slhdsa.SHA2_128s, slhdsa.SHA2_128f} {
		t.Run(ps.Name, func(t *testing.T) {
			alg, err := composite.AlgorithmForSLHDSA(ps)
			require.NoError(t, err)
			dir := t.TempDir()
			csp := newCompositeTestCSP(t, dir)

			k, err := csp.KeyGen(&bccsp.CompositeKeyGenOpts{OID: alg.OID, Temporary: false})
			require.NoError(t, err)
			pub, err := k.PublicKey()
			require.NoError(t, err)
			require.Equal(t, k.SKI(), pub.SKI())

			loaded, err := newCompositeTestCSP(t, dir).GetKey(k.SKI())
			require.NoError(t, err)
			sig, err := csp.Sign(loaded, msg, nil)
			require.NoError(t, err)
			valid, err := csp.Verify(pub, sig, msg, nil)
			require.NoError(t, err)
			require.True(t, valid)
			_, err = csp.Sign(loaded, msg, crypto.SHA256)
			require.Error(t, err)

			spki, err := pub.Bytes()
			require.NoError(t, err)
			fromPKIX, err := csp.KeyImport(spki, &bccsp.CompositePKIXPublicKeyImportOpts{Temporary: true})
			require.NoError(t, err)
			require.Equal(t, k.SKI(), fromPKIX.SKI())

			signer, err := bccspsigner.New(csp, k)
			require.NoError(t, err)
			goPub, ok := signer.Public().(*composite.PublicKey)
			require.True(t, ok)
			require.Equal(t, alg.Label, goPub.Algorithm.Label)
			sig, err = signer.Sign(rand.Reader, msg, &composite.SignerOpts{Context: []byte("ctx")})
			require.NoError(t, err)
			require.NoError(t, composite.Verify(goPub, msg, sig, []byte("ctx")))
		})
	}
}
