package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"runtime"
	"testing"
	"time"

	jwt "github.com/eclipse-xfsc/ssi-jwt"
	"github.com/eclipse-xfsc/ssi-jwt/fetcher"
	"github.com/spf13/viper"
)

func createJWKSServer(filename string) (*httptest.Server, error) {
	_, executor, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(executor), "..")
	err := os.Chdir(dir)

	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path.Join(dir, "tests", "data", filename))
	if err != nil {
		return nil, err
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Http Response:%s", string(data))
	}))

	return srv, nil
}

func createDIDServer() (*httptest.Server, error) {
	_, executor, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(executor), "..")
	err := os.Chdir(dir)

	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path.Join(dir, "tests", "data", "didResolution.json"))
	if err != nil {
		return nil, err
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Http Response:%s", string(data))
	}))

	viper.SetDefault("DID_RESOLVER", srv.URL)

	return srv, nil
}

func TestParseRequestWithoutJWK(t *testing.T) {

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := jwt.ParseRequest(r)

		if tok != nil && err == nil {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}

	}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)

	if resp.StatusCode == 200 || err != nil {
		t.Error()
	}
}

func TestParseRequestWithJWKsignedByJWKS(t *testing.T) {

	jwks, err := createJWKSServer("jwks.json")

	if err != nil {
		t.Error()
	}

	jwksFetcher := new(fetcher.JwksFetcher)
	jwksFetcher.Initialize([]string{jwks.URL}, time.Second)

	jwt.RegisterFetcher("JWKS1", jwksFetcher)
	signed, err, _ := CreateTestJWK(t, false)
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := jwt.ParseRequest(r)

		if tok != nil && err == nil {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}

	}))

	req, err := http.NewRequest("GET", srv.URL, nil)
	req.Header.Add("Authorization", "Bearer "+string(signed))
	if err != nil {
		t.Error()
	}

	resp, err := srv.Client().Do(req)

	if resp == nil || resp.StatusCode != 200 || err != nil {
		t.Log(resp)
		t.Error()
	}
	jwt.UnregisterFetcher("JWKS1")

	defer srv.Close()

	defer jwks.Close()
}

func TestParseRequestWithJWKsignedByDID(t *testing.T) {

	didServer, err := createDIDServer()

	if err != nil {
		t.Error()
	}

	didFetcher := new(fetcher.DidFetcher)
	err = didFetcher.Initialize([]string{"did:web:blub"}, time.Second)
	if err != nil {
		t.Error()
	}

	jwt.RegisterFetcher("DID1", didFetcher)
	signed, err, _ := CreateTestJWK(t, false)
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := jwt.ParseRequest(r)

		if tok != nil && err == nil {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}

	}))

	req, err := http.NewRequest("GET", srv.URL, nil)
	req.Header.Add("Authorization", "Bearer "+string(signed))
	if err != nil {
		t.Error()
	}

	resp, err := srv.Client().Do(req)

	if resp == nil || resp.StatusCode != 200 || err != nil {
		t.Error()
	}

	jwt.UnregisterFetcher("DID1")

	defer srv.Close()

	defer didServer.Close()
}
