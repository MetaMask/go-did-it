package jwk

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// Origin: https://github.com/w3c-ccg/did-key-spec/tree/main/test-vectors

func TestPrivateJwkRoundtrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{
			name: "RSA-2048",
			in: `{
			  "kty": "RSA",
			  "n": "sbX82NTV6IylxCh7MfV4hlyvaniCajuP97GyOqSvTmoEdBOflFvZ06kR_9D6ctt45Fk6hskfnag2GG69NALVH2o4RCR6tQiLRpKcMRtDYE_thEmfBvDzm_VVkOIYfxu-Ipuo9J_S5XDNDjczx2v-3oDh5-CIHkU46hvFeCvpUS-L8TJSbgX0kjVk_m4eIb9wh63rtmD6Uz_KBtCo5mmR4TEtcLZKYdqMp3wCjN-TlgHiz_4oVXWbHUefCEe8rFnX1iQnpDHU49_SaXQoud1jCaexFn25n-Aa8f8bc5Vm-5SeRwidHa6ErvEhTvf1dz6GoNPp2iRvm-wJ1gxwWJEYPQ",
			  "e": "AQAB",
			  "d": "Eym3sT4KLwBzo5pl5nY83-hAti92iLQRizkrKe22RbNi9Y1kKOBatdtGaJqFVztZZu5ERGKNuTd5VdsjJeekSbXviVGRtdHNCvgmRZlWA5261AgIUPxMmKW062GmGJbKQvscFfziBgHK6tyDBd8cZavqMFHi-7ilMYF7IsFBcJKM85x_30pnfd4YwhGQIc9hzv238aOwYKg8c-MzYhEVUnL273jaiLVlfZWQ5ca-GXJHmdOb_Y4fE5gpXfPFBseqleXsMp0VuXxCEsN30LIJHYscdPtbzLD3LFbuMJglFbQqYqssqymILGqJ7Tc2mB2LmXevfqRWz5D7A_K1WzvuoQ",
			  "p": "3CWT55Vc9CmUKavtV11fwwCU3lha99eRsl7Yo6HJLudpKV8zJ5bojTPqrowAjiHxyz3ITPCY3WgSX_q1n_4093U51rYermMfHQmrY_l7EgwxvNNMdsH4uMwHhz5vUNks6svtmkJL4JwQe8HPimHMdruCrPZKs0gajO59uNL-0rk",
			  "q": "zqcpEWpGAeJS0ZzTElrClcl6iQaElAV-KcOVqSOSm25FA2_QE7Px9FTGTrPDBivH5P9iT7SgAWwPypYiCJeDxZ_Rt1FbQvR0gfhzp9_eZJERd4BPaHdcNoXQXVgqezTxbJha064iJhYKHI72zB4rsBS5o4n7qWvqUSXNMYdV_6U",
			  "dp": "gcUE8rZxHNyFoiretWktUd2943Nh7Eb-c47FVW_BEA0JSIH9vZCPdOztogaVLTOFPLEmqXQKKDl422sGNVG8F0La3V5tp452gL96cGxXx8O4bf6ATGD7JLPgnDCJnbbna2Daptv9rmFQtiMBHCmaRUMzPJHSZuxR-lF7er-lxsE",
			  "dq": "Id2bCVOVLXHdiKReor9k7A8cmaAL0gYkasu2lwVRXU9w1-NXAiOXHydVaEhlSXmbRJflkJJVNmZzIAwCf830tko-oAAhKJPPFA2XRoeVdn2fkynf2YrV_cloICP2skI23kkJeW8sAXnTJmL3ZvP6zNxYn8hZCaa5u5qqSdeX7FE",
			  "qi": "WKIToXXnjl7GDbz7jCNbX9nWYOE5BDNzVmwiVOnyGoTZfwJ_qtgizj7pOapxi6dT9S9mMavmeAi6LAsEe1WUWtaKSNhbNh0PUGGXlXHGlhkS8jI1ot0e-scrHAuACE567YQ4VurpNorPKtZ5UENXIn74DEmt4l5m6902VF3X5Wo"
			}`,
		},
		{
			name: "RSA-4096",
			in: `{
			  "kty": "RSA",
			  "n": "qMCkFFRFWtzUyZeK8mgJdyM6SEQcXC5E6JwCRVDld-jlJs8sXNOE_vliexq34wZRQ4hk53-JPFlvZ_QjRgIxdUxSMiZ3S5hlNVvvRaue6SMakA9ugQhnfXaWORro0UbPuHLms-bg5StDP8-8tIezu9c1H1FjwPcdbV6rAvKhyhnsM10qP3v2CPbdE0q3FOsihoKuTelImtO110E7N6fLn4U3EYbC4OyViqlrP1o_1M-R-tiM1cb4pD7XKJnIs6ryZdfOQSPBJwjNqSdN6Py_tdrFgPDTyacSSdpTVADOM2IMAoYbhV1N5APhnjOHBRFyKkF1HffQKpmXQLBqvUNNjuhmpVKWBtrTdcCKrglFXiw0cKGHKxIirjmiOlB_HYHg5UdosyE3_1Txct2U7-WBB6QXak1UgxCzgKYBDI8UPA0RlkUuHHP_Zg0fVXrXIInHO04MYxUeSps5qqyP6dJBu_v_BDn3zUq6LYFwJ_-xsU7zbrKYB4jaRlHPoCj_eDC-rSA2uQ4KXHBB8_aAqNFC9ukWxc26Ifz9dF968DLuL30bi-ZAa2oUh492Pw1bg89J7i4qTsOOfpQvGyDV7TGhKuUG3Hbumfr2w16S-_3EI2RIyd1nYsflE6ZmCkZQMG_lwDAFXaqfyGKEDouJuja4XH8r4fGWeGTrozIoniXT1HU",
			  "e": "AQAB",
			  "d": "TMq1H-clVG7PihkjCqJbRFLMj9wmx6_qfauYwPBKK-HYfWujdW5vxBO6Q-jpqy7RxhiISmxYCBVuw_BuKMqQtR8Q_G9StBzaWYjHfn3Vp6Poz4umLqOjbI2NWNks_ybpGbd30oAK8V5ZkO04ozJpkN4i92hzK3mIc5-z1HiTNUPMn6cStab0VCn6em_ylltV774CEcRJ3OLgid7OUspRt_rID3qyreYbOulTu5WXHIGEnZDzrciIlz1dbcVldpUhD0VAP5ZErD2uUP5oztBNcTTn0YBF8CrOALuQVdaz_t_sNS3P0kWeT1eQ0QwDskO5Hw-Aey2tFeWk1bQyLoQ1A0jsw8mDbkO2zrGfJoxmVBkueTK-q64_n1kV7W1aeJFRj4NwEWmwcrs8GSOGOn38fGB_Y3Kci04qvD6L0QZbFkAVzcJracnxbTdHCEX0jsAAPbYC8M_8PyrPJvPC4IAAWTRrSRbysb7r7viRf4A1vTK9VT7uYyxj7Kzx2cU12d9QBXYfdQ2744bUE7HqN-Vh2rHvv2l5v6vzBRoZ5_OhHHVeUYwC9LouE9lSVAObbFM-Qe1SvzbbwN91LziI7UzUc_xMAEiNwt6PpnIAWAhdvSRawEllTwUcn89udHd5UhiAcm-RQOqXIdA9Aly6d8TT8R1p-ZnQ_gbZyBZeS39AuvU",
			  "p": "1p4cypsJeTyVXXc5bQpvzVenPy78OHXtGcFQnbTjW8x1GsvJ-rlHAcjUImd44pgNQNe-iYpeUg3KqfONeedNgQCFd8kP7GoVAd45mEvsGBXvjoCXOBMQlsf8UU_hm_LKhVvTvTmMGoudnNv5qYNDMCGJGzwoG-aSvROlIoXzHmDnusZ-hKsDxM9j0PPz21t99Y_Fr30Oq3FIWXPVmLYmfyZYQkxm9a9WNMkqRbwJuMwGI6V9ABsQ1dW_KJzp_aEBbJLcDr9DsWhm9ErLeAlzyaDYEai6wCtKm9em4LDwCbKhJq3hWEp1sIG-hwx1sk7N4i-b8lBijjEQE-dbSQxUlw",
			  "q": "yUqMejfrttGujadj7Uf7q91KM7nbQGny4TjD-CqibcFE-s2_DExCgP1wfhUPfJr2uPQDIe4g12uaNoa5GbCSDaQwEmQpurC_5mazt-z-_tbI24hoPQm5Hq67fZz-jDE_3OccLPLIWtajJqmxHbbB5VqskMuXo8KDxPRfBQBhykmb9_5M8pY2ggZOV4shCUn5E9nOnvibvw5Wx4CBtWUtca4rhpd3mVen1d8xCe4xTG_ni_w1lwdxzU1GmRFqgTuZWzL0r2FKzJg7hju1SOEe4tKMxQ-xs2HyNaMM__SLsNmS3lsYZ8r2hqcjEMQQZI0T_O-3BjIpyg986P8j055E0w",
			  "dp": "DujzJRw6P0L3OYQT6EBmXgSt6NTRzvZaX4SvnhU4CmOc6xynTpTamwQhwLYhjtRzb0LNyO5k-RxeLQpvlL1-A-1OWHEOeyUvim6u36a-ozm659KFLu8cIu2H2PpMuTHX4gXsIuRBmIKEk6YwpRcqbsiVpt-6BZ4yKZKY0Vou9rhSwQYTOhJLc7vYumaIVX_4szumxzdP8pcvKI_EkhRtfj3iudBnAsCIo6gqGKgkoMMD1iwkEALRW5m66w5jrywlVi6pvRiKkmOna2da1V8KvUJAYJGxT7JyP3tu64M_Wd0gFvjTg_fAT1_kJau27YlOAl2-Xso43poH_OoAzIVfxw",
			  "dq": "XI6Z76z9BxB9mgcpTLc3wzw63XQNnB3bn7JRcjBwhdVD2at3uLjsL5HaAy-98kbzQfJ56kUr9sI0o_Po8yYc0ob3z80c3wpdAx2gb-dbDWVH8KJVhBOPestPzR--cEpJGlNuwkBU3mgplyKaHZamq8a46M-lB5jurEbN1mfpj3GvdSYKzdVCdSFfLqP76eCI1pblinW4b-6w-oVdn0JJ1icHPpkxVmJW-2Hok69iHcqrBtRO9AZpTsTEvKekeI4mIyhYGLi9AzzQyhV0c3GImTXFoutng5t7GyzBUoRpI0W4YeQzYa6TEzGRTylIfGPemATF_OReENp0TlLbb3gsHw",
			  "qi": "m7uZk4AsOfJ1V2RY8lmEF518toCV7juKuS_b_OUx8B0dRG0_kbF1cH-Tmrgsya3bwkYx5HeZG81rX7SRjh-0nVPOMW3tGqU5U9f59DXqvOItJIJ6wvWvWXnuna2-NstYCotFQWadIKjk4wjEKj-a4NJt4D_F4csyeyqWOH2DiUFzBGGxxdEoD5t_HEeNXuWQ6-SiV0x5ZVMln3TSh7IOMl70Smm8HcQF5mOsWg3N0wIg-yffxPrs6r15TRuW1MfT-bZk2GLrtHF1TkIoT1e00jWK4eBl2oRxiJGONUBMTEHV85Fr0yztnA99AgHnrMbE_4ehvev4h5DEWvFyFuJN_g"
			}`,
		},
		{
			name: "ed25519",
			in: `{
				"kty": "OKP",
				"crv": "Ed25519",
				"x": "_eT7oDCtAC98L31MMx9J0T-w7HR-zuvsY08f9MvKne8",
				"d": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU"
			  }`,
		},
		{
			name: "p-256",
			in: `{
				"kty": "EC",
				"crv": "P-256",
				"x": "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns",
				"y": "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM",
				"d": "gPh-VvVS8MbvKQ9LSVVmfnxnKjHn4Tqj0bmbpehRlpc"
			  }`,
		},
		{
			name: "p-384",
			in: `{
				"kty": "EC",
				"crv": "P-384",
				"x": "lInTxl8fjLKp_UCrxI0WDklahi-7-_6JbtiHjiRvMvhedhKVdHBfi2HCY8t_QJyc",
				"y": "y6N1IC-2mXxHreETBW7K3mBcw0qGr3CWHCs-yl09yCQRLcyfGv7XhqAngHOu51Zv",
				"d": "hAyGZNj9031guBCdpAOaZkO-E5m-LKLYnMIq0-msrp8JLctseaOeNTHmP3uKVWwX"
			  }`,
		},
		{
			name: "p-521",
			in: `{
				"kty": "EC",
				"crv": "P-521",
				"x": "ASUHPMyichQ0QbHZ9ofNx_l4y7luncn5feKLo3OpJ2nSbZoC7mffolj5uy7s6KSKXFmnNWxGJ42IOrjZ47qqwqyS",
				"y": "AW9ziIC4ZQQVSNmLlp59yYKrjRY0_VqO-GOIYQ9tYpPraBKUloEId6cI_vynCzlZWZtWpgOM3HPhYEgawQ703RjC",
				"d": "AHwRaNaGs0jkj_pT6PK2aHep7dJK-yxyoL2bIfVRAceq1baxoiFDo3W14c8E2YZn1k5S53r4a11flhQdaB5guJ_X"
			  }`,
		},
		{
			name: "secp256k1",
			in: `{
				"kty": "EC",
				"crv": "secp256k1",
				"x": "TEIJN9vnTq1EXMkqzo7yN_867-foKc2pREv45Fw_QA8",
				"y": "9yiymlzdxKCiRbYq7p-ArRB-C1ytjHE-eb7RDTi6rVc",
				"d": "J5yKm7OXFsXDEutteGYeT0CAfQJwIlHLSYkQxKtgiyo"
			  }`,
		},
		{
			name: "x25519",
			in: `{
				"kty": "OKP",
				"crv": "X25519",
				"x": "jRIz3oriXDNZmnb35XQb7K1UIlz3ae1ao1YSqLeBXHs",
				"d": "aEAAB3VBFPCQtgF3N__wRiXhMOgeiRGstpPC3gnJ1Eo"
			  }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var priv PrivateJwk
			err := json.Unmarshal([]byte(tc.in), &priv)
			require.NoError(t, err)

			bytes, err := json.Marshal(priv)
			require.NoError(t, err)
			require.JSONEq(t, tc.in, string(bytes))
		})
	}
}
