package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	self "github.com/eclipse-xfsc/ssi-jwt/v2"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const testJwt = "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoiZGlkOmp3azpleUpyZEhraU9pSkZReUlzSW1OeWRpSTZJbEF0TWpVMklpd2llQ0k2SW04eGJrUk1ZbUZuVlVwWVpUWk9SalkxTjA0emNrMHlTalJUU0U1dVNYRTVVVnBDZUdoNWQzaGhkV01pTENKNUlqb2lNa3QzWnpCSk4yMDNlSEZLTFZNemFEaERTMWhRV2paalJFTlNTbTFpVTJKVldFSmxTblo1YmpkaFVTSjkjMCJ9.eyJhdWQiOiJodHRwczovL2Nsb3VkLXdhbGxldC5mYWNpcy5jbG91ZCIsImlhdCI6MTc2MjcyNDI0NiwiZXhwIjoxNzYyNzI0OTA2LCJub25jZSI6IjdlMTEyMTIwLTg0NzEtNDhiNy04MDBkLWZkNzc5Njg0NzcyYyIsImlzcyI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpGUXlJc0ltTnlkaUk2SWxBdE1qVTJJaXdpZUNJNkltOHhia1JNWW1GblZVcFlaVFpPUmpZMU4wNHpjazB5U2pSVFNFNXVTWEU1VVZwQ2VHaDVkM2hoZFdNaUxDSjVJam9pTWt0M1p6QkpOMjAzZUhGS0xWTXphRGhEUzFoUVdqWmpSRU5TU20xaVUySlZXRUpsU25aNWJqZGhVU0o5In0.aX61e230hkdSqZ2DzVTbUHU3ymRvRkahNGxU8Hp8GOoprtTGBKq77OAVoXRMAe4yAO1_L8_F1J2ywGjZnyw3xg"

const tokenString = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImVja2V5IiwidHlwIjoiYXQrand0In0.eyJhdWQiOlsidGVzdCJdLCJjb2RlIjoiTWRZSHFXSThCdFJiUmlzZXczaVoiLCJjcmVkZW50aWFsQ29uZmlndXJhdGlvbiI6eyJjb25maWd1cmF0aW9uX2lkIjoiRGV2ZWxvcGVyQ3JlZGVudGlhbCIsImNyZWRlbnRpYWxfaWRlbnRpZmllciI6bnVsbH0sImV4cCI6MTc3NCwiaWF0IjoxNzY0Mjc2MTQxLCJub25jZSI6IjdkZmUxYTEzLTNkMzItNDM5Yy1hM2E1LWU4MjQxNzkxODU3YyIsInN1YiI6ImZiNzg1ZTZhYjRiMmI0NjRjOTM2ZGFjZTRjOTRlMTE1NGUxZWU0M2I5YTE5N2E5M2RmZjYzOTgwYjg1ODYxOTIifQ.1h9HRQso-TYYRA6ftwliGwl5jT9mt6Bu3SSLWISL8I6DJ3w1UuWjpjqyTDgKpanoKi3DF6OYcGkkB1DgI3rQjw"

const kk = `{"alg":"ES256","crv":"P-256","kid":"eckey","kty":"EC","x":"jpfFo_zqiUMUY7FXZD4YAYLk7nl9YAZjyShN0nqOVUo","y":"tpdevD_1lEZmT0JmU0gxp9MFAPxwLVPL0X2ol8hQsqo"}`

func TestParseRequestES256(t *testing.T) {

	// --- 1. JWK laden ---
	keyset, err := jwk.Parse([]byte(kk))
	if err != nil {
		t.Fatalf("failed to parse JWK: %v", err)
	}

	// --- 2. HTTP Request bauen ---
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	// --- 3. ParseRequest + Signaturprüfung + exp ignorieren ---
	token, err := self.ParseRequest(
		req,
		jwt.WithKeySet(keyset),  // SIGNATURPRÜFUNG!
		jwt.WithValidate(false), // exp IGNORIEREN
	)
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}

	if token == nil {
		t.Fatal("expected token, got nil")
	}

	t.Log("Token successfully parsed + signature verified (exp ignored)")
}

func TestTokenParse33(t *testing.T) {

	// 1. JWK aus JSON laden
	keyset, err := jwk.Parse([]byte(kk))

	if err != nil {
		fmt.Errorf("failed to parse JWK: %w", err)
	}

	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(keyset), // falls kein kid im Token ist
		jwt.WithValidate(false),
	)

	if err != nil {
		fmt.Errorf("token validation failed: %w", err)
	}

	if token != nil {

	}
}

func TestTokenParse(t *testing.T) {
	signed, err, _ := CreateTestJWK(t, true)
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}

	token, err := self.Parse(string(signed))

	if err != nil || token == nil {
		t.Error()
	}
}

func TestTokenParse2(t *testing.T) {
	token, err := self.Parse(string(testJwt), jwt.WithValidate(false), jwt.WithVerify(true))

	if err != nil || token == nil {
		t.Error()
	}
}
