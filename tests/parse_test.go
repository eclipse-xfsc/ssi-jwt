package tests

import (
	"fmt"
	"testing"

	self "github.com/eclipse-xfsc/ssi-jwt"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const testJwt = "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoiZGlkOmp3azpleUpyZEhraU9pSkZReUlzSW1OeWRpSTZJbEF0TWpVMklpd2llQ0k2SW04eGJrUk1ZbUZuVlVwWVpUWk9SalkxTjA0emNrMHlTalJUU0U1dVNYRTVVVnBDZUdoNWQzaGhkV01pTENKNUlqb2lNa3QzWnpCSk4yMDNlSEZLTFZNemFEaERTMWhRV2paalJFTlNTbTFpVTJKVldFSmxTblo1YmpkaFVTSjkjMCJ9.eyJhdWQiOiJodHRwczovL2Nsb3VkLXdhbGxldC5mYWNpcy5jbG91ZCIsImlhdCI6MTc2MjcyNDI0NiwiZXhwIjoxNzYyNzI0OTA2LCJub25jZSI6IjdlMTEyMTIwLTg0NzEtNDhiNy04MDBkLWZkNzc5Njg0NzcyYyIsImlzcyI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpGUXlJc0ltTnlkaUk2SWxBdE1qVTJJaXdpZUNJNkltOHhia1JNWW1GblZVcFlaVFpPUmpZMU4wNHpjazB5U2pSVFNFNXVTWEU1VVZwQ2VHaDVkM2hoZFdNaUxDSjVJam9pTWt0M1p6QkpOMjAzZUhGS0xWTXphRGhEUzFoUVdqWmpSRU5TU20xaVUySlZXRUpsU25aNWJqZGhVU0o5In0.aX61e230hkdSqZ2DzVTbUHU3ymRvRkahNGxU8Hp8GOoprtTGBKq77OAVoXRMAe4yAO1_L8_F1J2ywGjZnyw3xg"

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
