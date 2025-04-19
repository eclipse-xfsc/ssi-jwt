package tests

import (
	"fmt"
	"testing"

	self "github.com/eclipse-xfsc/ssi-jwt"
)

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
