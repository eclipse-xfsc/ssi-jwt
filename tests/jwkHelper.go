package tests

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func CreateTestJWK(t *testing.T, didKid bool) ([]byte, error, jwk.Key) {

	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "..")
	err := os.Chdir(dir)

	data, err := os.ReadFile(path.Join(dir, "tests", "data", "testPriv.json"))
	if err != nil {
		t.Error(err)
		return nil, err, nil
	}

	privkey, err := jwk.ParseKey(data)

	if err != nil {
		t.Error(err)
		return nil, err, nil
	}

	pubkey, err := jwk.PublicKeyOf(privkey)

	if err != nil {
		fmt.Printf("failed to extract pub key: %s\n", err)
		return nil, err, nil
	}

	bytes, err := json.Marshal(pubkey)

	if err != nil {
		fmt.Printf("failed to marshal key: %s\n", err)
		return nil, err, nil
	}

	if didKid {
		privkey.Set("kid", "did:jwk:"+base64.RawURLEncoding.EncodeToString(bytes)+"#0")
		pubkey.Set("kid", "did:jwk:"+base64.RawURLEncoding.EncodeToString(bytes)+"#0")
	}

	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		IssuedAt(time.Now()).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return nil, err, nil
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.PS256, privkey))
	return signed, err, privkey
}
