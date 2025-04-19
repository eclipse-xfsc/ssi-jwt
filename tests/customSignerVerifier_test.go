package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/eclipse-xfsc/crypto-provider-core/types"
	self "github.com/eclipse-xfsc/ssi-jwt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestCustomSignerAndVerifier(t *testing.T) {

	provider := new(TestCryptoProvider)

	provider.CreateCryptoContext(types.CryptoContext{
		Namespace: "test",
		Context:   context.Background(),
	})

	p := types.CryptoKeyParameter{
		Identifier: types.CryptoIdentifier{
			KeyId: "testK",
			CryptoContext: types.CryptoContext{
				Namespace: "test",
				Context:   context.Background(),
			},
		},
		KeyType: types.Rsa4096,
	}
	err := provider.GenerateKey(p)

	if err != nil {
		t.Error()
	}

	self.EnableCryptoProvider(provider, true, true)

	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		IssuedAt(time.Now()).
		Build()

	if err != nil {
		t.Error()
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.PS256, "test/:testK"))
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}

	if signed == nil || err != nil {
		t.Error()
	}

	tok2, err := jwt.Parse(signed, jwt.WithKey(jwa.PS256, "test/:testK"))

	if tok2.Issuer() != tok.Issuer() || err != nil {
		t.Error()
	}

	self.DisableCryptoProvider()
}

func TestCustomSignerAndVerifierWithVeriferDisabled(t *testing.T) {

	provider := new(TestCryptoProvider)

	provider.CreateCryptoContext(types.CryptoContext{
		Namespace: "test",
		Context:   context.Background(),
	})

	p := types.CryptoKeyParameter{
		Identifier: types.CryptoIdentifier{
			KeyId: "testK",
			CryptoContext: types.CryptoContext{
				Namespace: "test",
				Context:   context.Background(),
			},
		},
		KeyType: types.Rsa4096,
	}
	err := provider.GenerateKey(p)

	if err != nil {
		t.Error()
	}

	self.EnableCryptoProvider(provider, true, false)

	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		IssuedAt(time.Now()).
		Build()

	if err != nil {
		t.Error()
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.PS256, "test/:testK"))
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}

	if signed == nil || err != nil {
		t.Error()
	}

	self.DisableCryptoProvider()

	_, err = jwt.Parse(signed, jwt.WithKey(jwa.PS256, "test/:testK"))

	if err == nil {
		t.Error()
	}

}
