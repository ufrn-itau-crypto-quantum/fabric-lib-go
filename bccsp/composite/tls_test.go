/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTLSCodepoint(t *testing.T) {
	require.Len(t, algorithms, 9)
	for i, alg := range algorithms {
		require.Equal(t, uint16(0xfe40+i), TLSCodepoint(alg), alg.Label)
		require.NotEmpty(t, TLSName(alg), alg.Label)
	}
	require.Equal(t, "mldsa44_ecdsa_p256_sha256", TLSName(algorithms[0]))
	require.Equal(t, uint16(0), TLSCodepoint(Algorithm{}))
}
