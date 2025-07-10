package jwk

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// Origin: https://github.com/w3c-ccg/did-key-spec/tree/main/test-vectors

func TestPublicJwkRoundtrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{
			name: "RSA",
			in: `{
				  "kty": "RSA",
				  "n": "sbX82NTV6IylxCh7MfV4hlyvaniCajuP97GyOqSvTmoEdBOflFvZ06kR_9D6ctt45Fk6hskfnag2GG69NALVH2o4RCR6tQiLRpKcMRtDYE_thEmfBvDzm_VVkOIYfxu-Ipuo9J_S5XDNDjczx2v-3oDh5-CIHkU46hvFeCvpUS-L8TJSbgX0kjVk_m4eIb9wh63rtmD6Uz_KBtCo5mmR4TEtcLZKYdqMp3wCjN-TlgHiz_4oVXWbHUefCEe8rFnX1iQnpDHU49_SaXQoud1jCaexFn25n-Aa8f8bc5Vm-5SeRwidHa6ErvEhTvf1dz6GoNPp2iRvm-wJ1gxwWJEYPQ",
				  "e": "AQAB"
				}`,
		},
		{
			name: "ed25519",
			in: `{
				"kty": "OKP",
				"crv": "Ed25519",
				"x": "_eT7oDCtAC98L31MMx9J0T-w7HR-zuvsY08f9MvKne8"
			  }`,
		},
		{
			name: "p-256",
			in: `{
				"kty": "EC",
				"crv": "P-256",
				"x": "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns",
				"y": "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM"
			  }`,
		},
		{
			name: "p-384",
			in: `{
				"kty": "EC",
				"crv": "P-384",
				"x": "lInTxl8fjLKp_UCrxI0WDklahi-7-_6JbtiHjiRvMvhedhKVdHBfi2HCY8t_QJyc",
				"y": "y6N1IC-2mXxHreETBW7K3mBcw0qGr3CWHCs-yl09yCQRLcyfGv7XhqAngHOu51Zv"
			  }`,
		},
		{
			name: "p-521",
			in: `{
				"kty": "EC",
				"crv": "P-521",
				"x": "ASUHPMyichQ0QbHZ9ofNx_l4y7luncn5feKLo3OpJ2nSbZoC7mffolj5uy7s6KSKXFmnNWxGJ42IOrjZ47qqwqyS",
				"y": "AW9ziIC4ZQQVSNmLlp59yYKrjRY0_VqO-GOIYQ9tYpPraBKUloEId6cI_vynCzlZWZtWpgOM3HPhYEgawQ703RjC"
			  }`,
		},
		{
			name: "secp256k1",
			in: `{
				"kty": "EC",
				"crv": "secp256k1",
				"x": "TEIJN9vnTq1EXMkqzo7yN_867-foKc2pREv45Fw_QA8",
				"y": "9yiymlzdxKCiRbYq7p-ArRB-C1ytjHE-eb7RDTi6rVc"
			  }`,
		},
		{
			name: "x25519",
			in: `{
				"kty": "OKP",
				"crv": "X25519",
				"x": "467ap28wHJGEXJAb4mLrokqq8A-txA_KmoQTcj31XzU"
			  }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pub PublicJwk
			err := json.Unmarshal([]byte(tc.in), &pub)
			require.NoError(t, err)

			bytes, err := json.Marshal(pub)
			require.NoError(t, err)
			require.JSONEq(t, tc.in, string(bytes))
		})
	}
}
