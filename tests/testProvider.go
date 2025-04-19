package tests

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"

	"github.com/eclipse-xfsc/crypto-provider-core/types"
)

var Plugin TestCryptoProvider //export Plugin Symbol, dont

type TestCryptoProvider struct{}

func (l *TestCryptoProvider) GetCryptoProvider() types.CryptoProvider {
	return new(TestCryptoProvider)
}

var namespaces = make(map[string]bool, 0)
var aesKeys = make(map[string]map[string][]byte, 0)
var rsaKeys = make(map[string]map[string]rsa.PrivateKey, 0)
var ecDsaKeys = make(map[string]map[string]ecdsa.PrivateKey, 0)
var edKeys = make(map[string]map[string]ed25519.PrivateKey, 0)

func (l TestCryptoProvider) CreateCryptoContext(context types.CryptoContext) error {
	ctx := buildPathNameSpace(context)
	namespaces[ctx] = true
	aesKeys[ctx] = make(map[string][]byte)
	rsaKeys[ctx] = make(map[string]rsa.PrivateKey)
	ecDsaKeys[ctx] = make(map[string]ecdsa.PrivateKey)
	edKeys[ctx] = make(map[string]ed25519.PrivateKey)
	return nil
}

func (l TestCryptoProvider) DestroyCryptoContext(context types.CryptoContext) error {
	ctx := buildPathNameSpace(context)
	delete(namespaces, ctx)
	delete(aesKeys, ctx)
	delete(rsaKeys, ctx)
	delete(ecDsaKeys, ctx)
	delete(edKeys, ctx)
	return nil
}

func buildPathNameSpace(context types.CryptoContext) string {
	return context.Namespace + "/" + context.Group
}

func (l TestCryptoProvider) IsCryptoContextExisting(context types.CryptoContext) (bool, error) {
	ctx := buildPathNameSpace(context)
	_, ok := namespaces[ctx]
	return ok, nil
}

func (l TestCryptoProvider) GetNamespaces(context types.CryptoContext) ([]string, error) {
	keys := make([]string, 0, len(namespaces))
	for k := range namespaces {
		keys = append(keys, k)
	}
	return keys, nil
}

func (l TestCryptoProvider) GetKey(parameter types.CryptoIdentifier) (*types.CryptoKey, error) {
	ctx := buildPathNameSpace(parameter.CryptoContext)
	key, ok := rsaKeys[ctx][parameter.KeyId]

	if ok {

		bytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)

		if err != nil {
			return nil, err
		}

		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: bytes,
		}

		pubkey_bytes := pem.EncodeToMemory(pemBlock)

		return &types.CryptoKey{
			Key:     pubkey_bytes,
			Version: "1",
			CryptoKeyParameter: types.CryptoKeyParameter{
				KeyType:    types.Rsa4096,
				Identifier: parameter,
			},
		}, nil
	}

	key2, ok2 := ecDsaKeys[ctx][parameter.KeyId]
	if ok2 {

		bytes, err := x509.MarshalPKIXPublicKey(&key2.PublicKey)

		if err != nil {
			return nil, err
		}

		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: bytes,
		}

		pubkey_bytes := pem.EncodeToMemory(pemBlock)
		return &types.CryptoKey{
			Key:     pubkey_bytes,
			Version: "1",
			CryptoKeyParameter: types.CryptoKeyParameter{
				KeyType:    types.Ecdsap256,
				Identifier: parameter,
			},
		}, nil

	}

	key3, ok3 := aesKeys[ctx][parameter.KeyId]

	if ok3 {
		return &types.CryptoKey{
			Key:     key3,
			Version: "1",
			CryptoKeyParameter: types.CryptoKeyParameter{
				KeyType:    types.Aes256GCM,
				Identifier: parameter,
			},
		}, nil
	}

	key4, ok4 := edKeys[ctx][parameter.KeyId]
	if ok4 {
		p := key4.Public().(ed25519.PublicKey)
		b := base64.StdEncoding.EncodeToString(p)
		if b != "" {
			dec, _ := base64.StdEncoding.DecodeString(b)
			if dec != nil {
				p2 := ed25519.PublicKey(dec)
				bytes, err := x509.MarshalPKIXPublicKey(p2)

				if bytes != nil && err != nil {

				}
			}
		}
		bytes, err := x509.MarshalPKIXPublicKey(key4.Public())

		if err != nil {
			return nil, err
		}

		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: bytes,
		}

		pubkey_bytes := pem.EncodeToMemory(pemBlock)
		return &types.CryptoKey{
			Key:     pubkey_bytes,
			Version: "1",
			CryptoKeyParameter: types.CryptoKeyParameter{
				KeyType:    types.Ed25519,
				Identifier: parameter,
			},
		}, nil

	}

	return nil, errors.New("key not found")
}

func (l TestCryptoProvider) IsKeyExisting(identifer types.CryptoIdentifier) (bool, error) {
	ctx := buildPathNameSpace(identifer.CryptoContext)
	_, ok := rsaKeys[ctx][identifer.KeyId]

	if ok {
		return true, nil
	}

	_, ok = ecDsaKeys[ctx][identifer.KeyId]

	if ok {
		return true, nil
	}

	_, ok = aesKeys[ctx][identifer.KeyId]

	if ok {
		return true, nil
	}

	_, ok = edKeys[ctx][identifer.KeyId]

	if ok {
		return true, nil
	}

	return false, nil
}

func (l TestCryptoProvider) GetKeys(parameter types.CryptoFilter) (*types.CryptoKeySet, error) {
	ctx := buildPathNameSpace(parameter.CryptoContext)
	set := new(types.CryptoKeySet)
	set.Keys = make([]types.CryptoKey, 0)

	_, ok := namespaces[ctx]

	if !ok {
		return nil, errors.New("namespace not existing.")
	}

	if parameter.Filter.String() == "" {
		reg, _ := regexp.Compile(".*")
		parameter.Filter = *reg
	}

	for i, _ := range aesKeys[ctx] {
		if parameter.Filter.MatchString(i) {
			identifier := types.CryptoIdentifier{
				CryptoContext: parameter.CryptoContext,
				KeyId:         i,
			}
			key, err := l.GetKey(identifier)

			if err != nil {
				return nil, err
			}

			set.Keys = append(set.Keys, *key)
		}

	}

	for i, _ := range rsaKeys[ctx] {
		if parameter.Filter.MatchString(i) {
			identifier := types.CryptoIdentifier{
				CryptoContext: parameter.CryptoContext,
				KeyId:         i,
			}
			key, err := l.GetKey(identifier)

			if err != nil {
				return nil, err
			}

			set.Keys = append(set.Keys, *key)
		}
	}

	for i, _ := range ecDsaKeys[ctx] {
		if parameter.Filter.MatchString(i) {
			identifier := types.CryptoIdentifier{
				CryptoContext: parameter.CryptoContext,
				KeyId:         i,
			}
			key, err := l.GetKey(identifier)

			if err != nil {
				return nil, err
			}

			set.Keys = append(set.Keys, *key)
		}
	}

	for i, _ := range edKeys[ctx] {
		if parameter.Filter.MatchString(i) {
			identifier := types.CryptoIdentifier{
				CryptoContext: parameter.CryptoContext,
				KeyId:         i,
			}
			key, err := l.GetKey(identifier)

			if err != nil {
				return nil, err
			}

			set.Keys = append(set.Keys, *key)
		}
	}

	return set, nil
}

func (l TestCryptoProvider) RotateKey(parameter types.CryptoIdentifier) error {
	return nil
}

func (l TestCryptoProvider) Hash(parameter types.CryptoHashParameter, msg []byte) (b []byte, err error) {
	if parameter.HashAlgorithm == types.Sha2256 {
		msgHash := sha256.New()
		_, err = msgHash.Write(msg)
		if err != nil {
			return nil, err
		}
		msgHashSum := msgHash.Sum(nil)
		return msgHashSum, nil
	} else {
		return nil, errors.ErrUnsupported
	}
}

func (l TestCryptoProvider) GenerateRandom(context types.CryptoContext, number int) ([]byte, error) {
	key := make([]byte, number)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (l TestCryptoProvider) Encrypt(parameter types.CryptoIdentifier, data []byte) ([]byte, error) {
	ctx := buildPathNameSpace(parameter.CryptoContext)

	_, ok := namespaces[ctx]

	if !ok {
		return nil, nil
	}

	key, ok := rsaKeys[ctx][parameter.KeyId]

	if ok {
		hash := sha256.New()
		ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, &key.PublicKey, data, nil)
		if err != nil {
			return nil, err
		}
		return ciphertext, err
	} else {
		key, ok := aesKeys[ctx][parameter.KeyId]

		if ok {
			c, err := aes.NewCipher(key)

			if err != nil {
				return nil, err
			}

			gcm, err := cipher.NewGCM(c)

			if err != nil {
				return nil, err
			}

			nonce, err := l.GenerateRandom(parameter.CryptoContext, gcm.NonceSize())

			if err != nil {
				return nil, err
			}

			return gcm.Seal(nonce, nonce, data, nil), nil
		}
	}

	return nil, errors.New("No key found.")
}

func (l TestCryptoProvider) Decrypt(parameter types.CryptoIdentifier, data []byte) ([]byte, error) {
	ctx := buildPathNameSpace(parameter.CryptoContext)

	_, ok := namespaces[ctx]

	if !ok {
		return nil, nil
	}

	key, ok := rsaKeys[ctx][parameter.KeyId]

	if ok {
		hash := sha256.New()
		ciphertext, err := rsa.DecryptOAEP(hash, rand.Reader, &key, data, nil)
		if err != nil {
			return nil, err
		}
		return ciphertext, err
	} else {
		key, ok := aesKeys[ctx][parameter.KeyId]

		if ok {
			c, err := aes.NewCipher(key)

			if err != nil {
				return nil, err
			}

			gcm, err := cipher.NewGCM(c)

			if err != nil {
				return nil, err
			}

			nonceSize := gcm.NonceSize()

			if len(data) < nonceSize {
				return nil, errors.New("Noncesize not valid.")
			}

			nonce, ciphertext := data[:nonceSize], data[nonceSize:]
			plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)

			if err != nil {
				return nil, err
			}

			return plaintext, nil
		}
	}
	return nil, errors.New("No key found.")
}

func (l TestCryptoProvider) Sign(parameter types.CryptoIdentifier, data []byte) (b []byte, err error) {
	ctx := buildPathNameSpace(parameter.CryptoContext)

	_, ok := namespaces[ctx]

	if !ok {
		return nil, nil
	}

	key, ok := rsaKeys[ctx][parameter.KeyId]

	if ok {
		hashed := sha256.Sum256(data)
		signature, err := rsa.SignPSS(rand.Reader, &key, crypto.SHA256, hashed[:], nil)
		if err != nil {
			return nil, err
		}

		return signature, nil
	}

	key2, ok := ecDsaKeys[ctx][parameter.KeyId]

	if ok {

		hashed := sha256.Sum256(data)
		signature, err := ecdsa.SignASN1(rand.Reader, &key2, hashed[:])
		if err != nil {
			return nil, err
		}

		return signature, nil
	}

	key3, ok := edKeys[ctx][parameter.KeyId]

	if ok {
		hashed := sha256.Sum256(data)
		signature := ed25519.Sign(key3, hashed[:])
		return signature, nil
	}

	return nil, errors.ErrUnsupported
}

func (l TestCryptoProvider) Verify(parameter types.CryptoIdentifier, data []byte, signature []byte) (b bool, err error) {

	ctx := buildPathNameSpace(parameter.CryptoContext)

	_, ok := namespaces[ctx]

	if !ok {
		return false, nil
	}

	key, ok := rsaKeys[ctx][parameter.KeyId]
	if ok {
		hashed := sha256.Sum256(data)
		err = rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, hashed[:], signature, nil)
		if err == nil {
			return true, nil
		}
	}

	key2, ok := ecDsaKeys[ctx][parameter.KeyId]
	if ok {
		hashed := sha256.Sum256(data)
		result := ecdsa.VerifyASN1(&key2.PublicKey, hashed[:], signature)
		return result, nil

	}

	key3, ok := edKeys[ctx][parameter.KeyId]
	if ok {
		hashed := sha256.Sum256(data)
		result := ed25519.Verify(key3.Public().(ed25519.PublicKey), hashed[:], signature)
		return result, nil

	}

	fmt.Println("could not verify signature: ", err)
	return false, errors.ErrUnsupported
}

func (l TestCryptoProvider) DeleteKey(parameter types.CryptoIdentifier) error {
	delete(rsaKeys, parameter.KeyId)
	delete(ecDsaKeys, parameter.KeyId)
	delete(aesKeys, parameter.KeyId)
	return nil
}

func (l TestCryptoProvider) GenerateKey(parameter types.CryptoKeyParameter) error {
	ctx := buildPathNameSpace(parameter.Identifier.CryptoContext)

	_, ok := namespaces[ctx]

	if !ok {
		return errors.New("namespace not found.")
	}

	if parameter.KeyType == types.Rsa4096 {

		_, ok := rsaKeys[ctx][parameter.Identifier.KeyId]

		if !ok {
			keyNew, err := rsa.GenerateKey(rand.Reader, 4096)
			if err != nil {
				return err
			}
			rsaKeys[ctx][parameter.Identifier.KeyId] = *keyNew
		}
		return nil
	}

	if parameter.KeyType == types.Ecdsap256 {

		_, ok := ecDsaKeys[ctx][parameter.Identifier.KeyId]

		if !ok {
			keyNew, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			ecDsaKeys[ctx][parameter.Identifier.KeyId] = *keyNew
		}

		return nil
	}

	if parameter.KeyType == types.Ed25519 {

		_, ok := edKeys[ctx][parameter.Identifier.KeyId]

		if !ok {
			_, keyNew, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			edKeys[ctx][parameter.Identifier.KeyId] = keyNew
		}

		return nil
	}

	if parameter.KeyType == types.Aes256GCM {
		_, ok := aesKeys[ctx][parameter.Identifier.KeyId]

		if !ok {
			keyNew, err := l.GenerateRandom(parameter.Identifier.CryptoContext, 32)
			if err != nil {
				return err
			}
			aesKeys[ctx][parameter.Identifier.KeyId] = keyNew
			return nil
		}
	}

	return errors.ErrUnsupported
}

func (l TestCryptoProvider) GetSeed(context context.Context) string {
	ctx := types.CryptoContext{
		Namespace: "random",
		Context:   context,
	}
	b, _ := l.GenerateRandom(ctx, 32)
	return b64.StdEncoding.EncodeToString(b)
}

func (l TestCryptoProvider) GetSupportedHashAlgs() []types.HashAlgorithm {
	return []types.HashAlgorithm{types.Sha2256}
}

func (l TestCryptoProvider) GetSupportedKeysAlgs() []types.KeyType {
	return []types.KeyType{types.Ecdsap256, types.Aes256GCM, types.Rsa4096, types.Ed25519}
}
