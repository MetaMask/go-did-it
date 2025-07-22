package didplc_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-did-it"
)

func TestParseDIDPlc(t *testing.T) {
	str := "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
	d, err := did.Parse(str)
	require.NoError(t, err)
	require.Equal(t, str, d.String())
}

func TestIncorrectDIDPlc(t *testing.T) {
	tests := []string{
		"did:plc:ewvi7nxzyoun6zhxrhs64oi",   // too short
		"did:plc:ewvi7nxzyoun6zhxrhs64oizz", // too long
		"did:plc:ewvi7nxzyoun6zhxrhs64oi0",  // wrong char
		"did:plc:ewvi7nxzyoun6zhxrhs64oiz:", // extra :
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			_, err := did.Parse(tt)
			require.Error(t, err)
		})
	}
}

func TestMustParseDIDPlc(t *testing.T) {
	str := "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
	require.NotPanics(t, func() {
		d := did.MustParse(str)
		require.Equal(t, str, d.String())
	})
	str = "did:plc:ewvi7nxzyoun6zhxrhs6" // too short
	require.Panics(t, func() {
		did.MustParse(str)
	})
}
