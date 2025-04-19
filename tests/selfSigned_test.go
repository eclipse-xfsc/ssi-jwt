package tests

import (
	"fmt"
	"testing"
	"time"

	self "github.com/eclipse-xfsc/ssi-jwt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestSelfSignedForNil(t *testing.T) {
	self.ParseSelfSigned("", nil, nil)
	self.ParseSelfSigned("", nil)
}

func TestSelfSignedTokenValidation(t *testing.T) {

	signed, err, privkey := CreateTestJWK(t, false)
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}

	pubkey, err := jwk.PublicKeyOf(privkey)
	if err != nil {
		t.Error(err)
		return
	}

	t.Logf("%s\n", signed)

	token, err := self.ParseSelfSigned(string(signed))

	if err == nil || token != nil {
		t.Error()
	}

	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		IssuedAt(time.Now()).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	headers := jws.NewHeaders()
	headers.Set("jwk", pubkey)

	signed, err = jwt.Sign(tok, jwt.WithKey(jwa.PS256, privkey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}

	t.Logf("%s\n", signed)

	token, err = self.ParseSelfSigned(string(signed))

	if err != nil || token == nil {
		t.Error()
	}

	token, err = self.ParseSelfSigned(string(signed))

	if err != nil || token == nil {
		t.Error()
	}
}
