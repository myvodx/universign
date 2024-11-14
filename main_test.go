package main

import (
	"testing"
)

func TestVerifyWebhookSignature(t *testing.T) {
	type args struct {
		signature string
		body      string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			"Test VerifyWebhookSignature",
			args{
				signature: "eyJhbGciOiJQUzI1NiIsICJraWQiOiJzY2RfZWE5MGI1NzhiNTVhZDg4OTNkMzdmY2RkOGMyM2E4OTU2YmRhYmIxYmU0ZGNiMWYxNzBkYmJkMDRlOTg3ODk2ZSJ9..GG3rOkYgO6bg6tMn8c_-EtZOK0QTqYBrluRLJIAEdDHKqjEM5-WUyUSJJRLLnPmzJZxJuM6rDSP2_MKDgoTzemyrg-n-E9MvmENxedm7K5khPxHLGepLQpAqTG5p25WRiBRwa9vAUOdq2j_57lSwlwioBGoh__LpZeVdvUYxghMQEZ7ZFuMsaIqL0fiPfpj2XyP9LS6MP65ElxZFrJSR9lyI6ywH9GVGEKTjabfzjBSI-tZnIM1MySm_syTz5rt90YqkRyGOPMaZscuRd7_pm1DHQw8d9N6D-_nUEy5IXicCDAeBM44BouMI-Fdq21TCMQIqacp37k1jFJRYq75NdHjwYo3gDMfDO_CQH8Qp1sPECQBlFPqIH5YtE0Lc5T_phwO9SC7-qV1HxfuvodS-HwraOIM7PtEGMoV_fiieAGTobKMGHRHQ-UNKnRGzS0ovrNveEvOvIYE5FR-irUeOwFXproZw1k_caq1TiAgcEp3xEU0-w6jekdTXX92pvIo15Cdp3iRD4zS2G2YRLrl6HItdPwmn1kEXQhzdoFcSVUIn_0oJUqTP8naK9_AeKkdCEDdLghZTh16Zgx1tojtbrXAjyYQw8MlEu_uOQK3IJGiTS3xliSOYuLonRdAWAhI06Y-r1XS4lDFiuIcidlkwrVRsM3EO_0DG0YfF9Or2s1M",
				body:      "{}",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyWebhookSignature(tt.args.signature, tt.args.body)
			if err != nil {
				t.Errorf("VerifyWebhookSignature() error = %v, signature: %v, body: %v", err, tt.args.signature, tt.args.body)

			}
		})
	}
}
