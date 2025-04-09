package didkey_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/INFURA/go-did"
	_ "github.com/INFURA/go-did/methods/did-key"
)

func TestParseDIDKey(t *testing.T) {
	str := "did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z"
	d, err := did.Parse(str)
	require.NoError(t, err)
	require.Equal(t, str, d.String())
}

func TestMustParseDIDKey(t *testing.T) {
	str := "did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z"
	require.NotPanics(t, func() {
		d := did.MustParse(str)
		require.Equal(t, str, d.String())
	})
	str = "did:key:z7Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z"
	require.Panics(t, func() {
		did.MustParse(str)
	})
}

func TestEquivalence(t *testing.T) {
	did0A, err := did.Parse("did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z")
	require.NoError(t, err)
	did0B, err := did.Parse("did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z")
	require.NoError(t, err)
	did1, err := did.Parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
	require.NoError(t, err)

	require.True(t, did0A.Equal(did0B))
	require.False(t, did0A.Equal(did1))
}
