/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package slhdsa_test

import (
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/stretchr/testify/require"
)

func TestTLSCodepoint(t *testing.T) {
	sets := slhdsa.ParameterSets()
	require.Len(t, sets, 12)
	for i, ps := range sets {
		require.Equal(t, uint16(0x0911+i), slhdsa.TLSCodepoint(ps), ps.Name)
	}
	require.Equal(t, uint16(0x0911), slhdsa.TLSCodepoint(slhdsa.SHA2_128s))
	require.Equal(t, uint16(0x091c), slhdsa.TLSCodepoint(slhdsa.SHAKE_256f))
}
