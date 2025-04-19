package tests

import (
	"fmt"
	"testing"

	jwt "github.com/eclipse-xfsc/ssi-jwt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
)

func TestCreateJweMessage(t *testing.T) {

	_, err, privKey := CreateTestJWK(t, false)
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}

	pubKey, err := privKey.PublicKey()

	if err != nil {
		t.Error()
	}

	test := "Test"

	msg := jwt.EncryptJweMessage([]byte(test), jwa.RSA_OAEP_256, pubKey)

	if msg == nil {
		t.Error()
	}

	payload, err := jwt.DecryptJweMessage(msg, jwe.WithKey(jwa.RSA_OAEP_256, privKey))

	if err != nil {
		t.Error()
	}

	if string(payload) != test {
		t.Error()
	}
}
