package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	self "github.com/eclipse-xfsc/ssi-jwt/v2"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const testJwt = "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoiZGlkOmp3azpleUpyZEhraU9pSkZReUlzSW1OeWRpSTZJbEF0TWpVMklpd2llQ0k2SW04eGJrUk1ZbUZuVlVwWVpUWk9SalkxTjA0emNrMHlTalJUU0U1dVNYRTVVVnBDZUdoNWQzaGhkV01pTENKNUlqb2lNa3QzWnpCSk4yMDNlSEZLTFZNemFEaERTMWhRV2paalJFTlNTbTFpVTJKVldFSmxTblo1YmpkaFVTSjkjMCJ9.eyJhdWQiOiJodHRwczovL2Nsb3VkLXdhbGxldC5mYWNpcy5jbG91ZCIsImlhdCI6MTc2MjcyNDI0NiwiZXhwIjoxNzYyNzI0OTA2LCJub25jZSI6IjdlMTEyMTIwLTg0NzEtNDhiNy04MDBkLWZkNzc5Njg0NzcyYyIsImlzcyI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpGUXlJc0ltTnlkaUk2SWxBdE1qVTJJaXdpZUNJNkltOHhia1JNWW1GblZVcFlaVFpPUmpZMU4wNHpjazB5U2pSVFNFNXVTWEU1VVZwQ2VHaDVkM2hoZFdNaUxDSjVJam9pTWt0M1p6QkpOMjAzZUhGS0xWTXphRGhEUzFoUVdqWmpSRU5TU20xaVUySlZXRUpsU25aNWJqZGhVU0o5In0.aX61e230hkdSqZ2DzVTbUHU3ymRvRkahNGxU8Hp8GOoprtTGBKq77OAVoXRMAe4yAO1_L8_F1J2ywGjZnyw3xg"

const tokenString = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImVja2V5IiwidHlwIjoiYXQrand0In0.eyJhdWQiOlsidGVzdCJdLCJjb2RlIjoiTWRZSHFXSThCdFJiUmlzZXczaVoiLCJjcmVkZW50aWFsQ29uZmlndXJhdGlvbiI6eyJjb25maWd1cmF0aW9uX2lkIjoiRGV2ZWxvcGVyQ3JlZGVudGlhbCIsImNyZWRlbnRpYWxfaWRlbnRpZmllciI6bnVsbH0sImV4cCI6MTc3NCwiaWF0IjoxNzY0Mjc2MTQxLCJub25jZSI6IjdkZmUxYTEzLTNkMzItNDM5Yy1hM2E1LWU4MjQxNzkxODU3YyIsInN1YiI6ImZiNzg1ZTZhYjRiMmI0NjRjOTM2ZGFjZTRjOTRlMTE1NGUxZWU0M2I5YTE5N2E5M2RmZjYzOTgwYjg1ODYxOTIifQ.1h9HRQso-TYYRA6ftwliGwl5jT9mt6Bu3SSLWISL8I6DJ3w1UuWjpjqyTDgKpanoKi3DF6OYcGkkB1DgI3rQjw"

const kk = `{"alg":"ES256","crv":"P-256","kid":"eckey","kty":"EC","x":"jpfFo_zqiUMUY7FXZD4YAYLk7nl9YAZjyShN0nqOVUo","y":"tpdevD_1lEZmT0JmU0gxp9MFAPxwLVPL0X2ol8hQsqo"}`

func TestParseRequestWithJWKS(t *testing.T) {

	var requestCount atomic.Int32

	jwksServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount.Add(1)

			if r.Method != http.MethodGet {
				t.Errorf("expected GET request, got %s", r.Method)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			// kk enthält einen einzelnen JWK. Ein JWKS benötigt ein keys-Array.
			if _, err := fmt.Fprintf(w, `{"keys":[%s]}`, kk); err != nil {
				t.Errorf("failed to write JWKS response: %v", err)
			}
		}),
	)
	defer jwksServer.Close()

	parseToken := func() jwt.Token {
		t.Helper()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		token, err := self.ParseRequestWithJWKS(
			req,
			jwksServer.URL,
			jwt.WithValidate(false),
		)
		if err != nil {
			t.Fatalf("ParseRequestWithJWKS failed: %v", err)
		}

		if token == nil {
			t.Fatal("expected token, got nil")
		}

		return token
	}

	firstToken := parseToken()
	secondToken := parseToken()

	if firstToken == nil || secondToken == nil {
		t.Fatal("expected both tokens to be parsed")
	}

	if got := requestCount.Load(); got != 1 {
		t.Fatalf(
			"expected JWKS endpoint to be called once due to caching, got %d calls",
			got,
		)
	}
}

func TestParseRequestWithJWKS_InvalidJWKSBody(t *testing.T) {
	jwksServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("expected GET request, got %s", r.Method)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			// Kein gültiges JWKS
			_, _ = w.Write([]byte(`[]`))
		}),
	)
	defer jwksServer.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	token, err := self.ParseRequestWithJWKS(
		req,
		jwksServer.URL,
		jwt.WithValidate(false),
	)

	if token != nil {
		t.Fatalf("expected token to be nil, got %v", token)
	}

	if err == nil {
		t.Fatal("expected error because response body is not a valid JWKS")
	}

	t.Logf("received expected error: %v", err)
}

func TestParseRequestWithJWKS_URLNotReachable(t *testing.T) {
	jwksServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("server should not receive a request")
		}),
	)

	// Server sofort schließen.
	// Die URL bleibt bestehen, aber auf dem Port lauscht niemand mehr.
	jwksURL := jwksServer.URL
	jwksServer.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	token, err := self.ParseRequestWithJWKS(
		req,
		jwksURL,
		jwt.WithValidate(false),
	)

	if token != nil {
		t.Fatalf("expected token to be nil, got: %v", token)
	}

	if err == nil {
		t.Fatal("expected error because JWKS URL is unreachable, got nil")
	}

	t.Logf("received expected connection error: %v", err)
}

func TestParseRequestWithJWKS_RetryNetworkErrorInvalidSetThenSuccessAndCache(
	t *testing.T,
) {
	var requestCount atomic.Int32

	jwksServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := requestCount.Add(1)

			if r.Method != http.MethodGet {
				t.Errorf(
					"expected GET request, got %s",
					r.Method,
				)
			}

			switch count {
			case 1:
				// ------------------------------------------------
				// 1. Versuch:
				// Netzwerkfehler simulieren.
				//
				// Die Verbindung wird geschlossen, bevor eine
				// HTTP Response zurückgegeben wird.
				// ------------------------------------------------
				hijacker, ok := w.(http.Hijacker)
				if !ok {
					t.Fatal("ResponseWriter does not support hijacking")
				}

				conn, _, err := hijacker.Hijack()
				if err != nil {
					t.Fatalf(
						"failed to hijack connection: %v",
						err,
					)
				}

				_ = conn.Close()
				return

			case 2:
				// ------------------------------------------------
				// 2. Versuch:
				// HTTP funktioniert wieder, aber das JWKS ist
				// syntaktisch gültig und enthält keine Keys.
				// ------------------------------------------------
				w.Header().Set(
					"Content-Type",
					"application/json",
				)

				w.WriteHeader(http.StatusOK)

				_, _ = w.Write(
					[]byte(`{"keys":[]}`),
				)

				return

			default:
				// ------------------------------------------------
				// 3. Versuch:
				// Jetzt kommt ein gültiges JWKS.
				// ------------------------------------------------
				w.Header().Set(
					"Content-Type",
					"application/json",
				)

				w.WriteHeader(http.StatusOK)

				_, err := fmt.Fprintf(
					w,
					`{"keys":[%s]}`,
					kk,
				)
				if err != nil {
					t.Errorf(
						"failed to write JWKS response: %v",
						err,
					)
				}
			}
		}),
	)
	defer jwksServer.Close()

	// ============================================================
	// FIRST REQUEST
	//
	// Erwartung:
	//
	// Request 1 -> Netzwerkfehler
	// Request 2 -> leeres JWKS
	// Request 3 -> gültiges JWKS
	//
	// Danach muss der Token erfolgreich geparsed werden.
	// ============================================================

	req := httptest.NewRequest(
		http.MethodGet,
		"/",
		nil,
	)

	req.Header.Set(
		"Authorization",
		"Bearer "+tokenString,
	)

	token, err := self.ParseRequestWithJWKS(
		req,
		jwksServer.URL,
		jwt.WithValidate(false),
	)

	if err != nil {
		t.Fatalf(
			"expected ParseRequestWithJWKS to succeed after retries, got: %v",
			err,
		)
	}

	if token == nil {
		t.Fatal(
			"expected token after successful JWKS retry, got nil",
		)
	}

	// Es müssen genau 3 Versuche stattgefunden haben.
	if got := requestCount.Load(); got != 3 {
		t.Fatalf(
			"expected exactly 3 JWKS requests, got %d",
			got,
		)
	}

	// ============================================================
	// SECOND REQUEST
	//
	// Das erfolgreiche Key Set muss jetzt im Cache liegen.
	//
	// Die JWKS URL darf NICHT erneut aufgerufen werden.
	// ============================================================

	requestsBeforeSecondParse := requestCount.Load()

	req2 := httptest.NewRequest(
		http.MethodGet,
		"/",
		nil,
	)

	req2.Header.Set(
		"Authorization",
		"Bearer "+tokenString,
	)

	token2, err := self.ParseRequestWithJWKS(
		req2,
		jwksServer.URL,
		jwt.WithValidate(false),
	)

	if err != nil {
		t.Fatalf(
			"expected second ParseRequestWithJWKS to use cached JWKS, got: %v",
			err,
		)
	}

	if token2 == nil {
		t.Fatal(
			"expected token from cached JWKS, got nil",
		)
	}

	requestsAfterSecondParse := requestCount.Load()

	// ------------------------------------------------------------
	// Wichtigste Cache-Prüfung:
	//
	// Zwischen Parse #1 und Parse #2 darf KEIN weiterer Request
	// an die JWKS URL gegangen sein.
	// ------------------------------------------------------------
	if requestsAfterSecondParse != requestsBeforeSecondParse {
		t.Fatalf(
			"expected second parse to use cached JWKS without accessing URL; "+
				"requests before=%d, after=%d",
			requestsBeforeSecondParse,
			requestsAfterSecondParse,
		)
	}

	if requestsAfterSecondParse != 3 {
		t.Fatalf(
			"expected total JWKS request count to remain 3, got %d",
			requestsAfterSecondParse,
		)
	}
}

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
