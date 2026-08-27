package jwt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	cryptoCore "github.com/eclipse-xfsc/crypto-provider-core/v2/types"
	"github.com/eclipse-xfsc/did-core/v2"
	"github.com/eclipse-xfsc/ssi-jwt/v2/types"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	ljwt "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/sirupsen/logrus"
)

var fetchers map[string]types.KeyFetcher = make(map[string]types.KeyFetcher)

var (
	jwksCacheContext = context.Background()
	jwksCache        = jwk.NewCache(jwksCacheContext)
	jwksCacheMutex   sync.Mutex
	successfulJWKS   sync.Map // map[string]jwk.Set
)

const maxJWKSFetchAttempts = 10

func RegisterFetcher(id string, fetcher types.KeyFetcher) {
	fetchers[id] = fetcher
}

func UnregisterFetcher(id string) {
	fetcher, ok := fetchers[id]
	if ok {
		delete(fetchers, id)
		fetcher.Stop()
	}
}

func EnableCryptoProvider(cryptoprovider cryptoCore.CryptoProvider, sign bool, verify bool) {
	new(types.SignerInterceptor).CreateInterceptor(jwa.PS256, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.PS384, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.PS512, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.ES256, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.ES384, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.ES512, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.EdDSA, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.SignatureAlgorithm(jwa.Ed25519), cryptoprovider, sign, verify)
}

func DisableCryptoProvider(sign bool, verify bool) {

	if verify {
		jws.UnregisterVerifier(jwa.PS256)
		jws.UnregisterVerifier(jwa.PS384)
		jws.UnregisterVerifier(jwa.PS512)
		jws.UnregisterVerifier(jwa.ES256)
		jws.UnregisterVerifier(jwa.ES384)
		jws.UnregisterVerifier(jwa.ES512)
		jws.UnregisterVerifier(jwa.EdDSA)
		jws.UnregisterVerifier(jwa.SignatureAlgorithm(jwa.Ed25519))
	}

	if sign {
		jws.UnregisterSigner(jwa.PS256)
		jws.UnregisterSigner(jwa.PS384)
		jws.UnregisterSigner(jwa.PS512)
		jws.UnregisterSigner(jwa.ES256)
		jws.UnregisterSigner(jwa.ES384)
		jws.UnregisterSigner(jwa.ES512)
		jws.UnregisterSigner(jwa.EdDSA)
		jws.UnregisterSigner(jwa.SignatureAlgorithm(jwa.Ed25519))
	}

	if sign && verify {
		jwa.UnregisterSignatureAlgorithm(jwa.PS256)
		jwa.UnregisterSignatureAlgorithm(jwa.PS384)
		jwa.UnregisterSignatureAlgorithm(jwa.PS512)
		jwa.UnregisterSignatureAlgorithm(jwa.ES256)
		jwa.UnregisterSignatureAlgorithm(jwa.ES384)
		jwa.UnregisterSignatureAlgorithm(jwa.ES512)
		jwa.UnregisterSignatureAlgorithm(jwa.EdDSA)
		jwa.UnregisterSignatureAlgorithm(jwa.SignatureAlgorithm(jwa.Ed25519))
	}
}

func Parse(tokenString string, options ...ljwt.ParseOption) (ljwt.Token, error) {
	if tokenString == "" {
		return nil, ljwt.ErrInvalidJWT()
	}

	didKidOption := ljwt.WithKeyProvider(jws.KeyProviderFunc(func(ctx context.Context,
		ks jws.KeySink,
		s *jws.Signature,
		m *jws.Message) error {

		alg := s.ProtectedHeaders().Algorithm()

		kid := s.ProtectedHeaders().KeyID()
		key := s.ProtectedHeaders().JWK()
		//if no kid is provided, the jwk embedding is used, jwk used directly
		if kid == "" && key != nil {
			ks.Key(alg, key)
			return nil
		} else {
			//direct key reference to did doc
			if strings.Contains(kid, "did:") && strings.Contains(kid, "#") {
				id := strings.Split(kid, "#")

				document, err := did.Resolve(id[0])

				if err != nil {
					return nil
				}

				set := document.GetPublicKeys()
				key, ok := set.LookupKeyID("#" + id[1])

				if ok {
					ks.Key(alg, key)
				} else {
					key, ok := set.LookupKeyID(kid)
					if ok {
						ks.Key(alg, key)
					}
				}
			} else {
				return errors.New("kid not resolvable did with fragment")
			}
		}

		return nil
	}))

	options = append(options, didKidOption)
	return ljwt.Parse([]byte(tokenString), options...)
}

func CombineJwksSets(sets []jwk.Set, context context.Context) jwk.Set {
	combinedSet := jwk.NewSet()
	for _, item := range sets {
		iterator := item.Keys(context)
		for i := 0; i < item.Len(); i++ {
			if iterator.Next(context) {
				key := iterator.Pair().Value.(jwk.Key)

				_, exist := combinedSet.LookupKeyID(key.KeyID())

				if exist {
					logrus.Error("Key " + key.KeyID() + " already exist or is twice available. Key was NOT ADDED to set")
				} else {
					err := combinedSet.AddKey(key)
					if err != nil {
						logrus.Error("Key " + key.KeyID() + " already exist or is twice available. Key was NOT ADDED to set")
					}
				}
			}
		}
	}
	return combinedSet
}

func ParseRequest(r *http.Request, options ...ljwt.ParseOption) (ljwt.Token, error) {
	var sets []jwk.Set
	for _, f := range fetchers {
		keys, err := f.GetKeys()
		if err == nil {
			sets = append(sets, keys)
		} else {
			logrus.Error(err)
		}
	}

	keySetOption := ljwt.WithKeySet(CombineJwksSets(sets, context.Background()))
	options = append(options, keySetOption)
	return ljwt.ParseRequest(r, options...)
}

func ParseRequestWithJWKS(
	r *http.Request,
	jwksURL string,
	options ...ljwt.ParseOption,
) (ljwt.Token, error) {

	if r == nil {
		return nil, errors.New("request must not be nil")
	}

	jwksURL = strings.TrimSpace(jwksURL)
	if jwksURL == "" {
		return ParseRequest(r, options...)
	}

	var remoteSet jwk.Set

	// ------------------------------------------------------------
	// 1. Erfolgreich geladenes JWKS vorhanden?
	//
	// Dann KEIN Fetch mehr.
	// ------------------------------------------------------------
	if cached, ok := successfulJWKS.Load(jwksURL); ok {
		set, ok := cached.(jwk.Set)
		if ok && set != nil && set.Len() > 0 {
			remoteSet = set
		} else {
			// Defensive cleanup, falls aus irgendeinem Grund
			// ungültige Daten im Cache landen.
			successfulJWKS.Delete(jwksURL)
		}
	}

	// ------------------------------------------------------------
	// 2. Noch kein erfolgreiches Set vorhanden -> laden.
	// ------------------------------------------------------------
	if remoteSet == nil {

		// Lock absichtlich über den gesamten Fetch-Vorgang.
		//
		// Dadurch verhindern wir z.B.:
		//
		// goroutine 1 -> fetch attempt 1..10
		// goroutine 2 -> fetch attempt 1..10
		// goroutine 3 -> fetch attempt 1..10
		//
		// für dieselbe URL.
		jwksCacheMutex.Lock()

		// Double-check:
		// Vielleicht hat eine andere Goroutine das Set geladen,
		// während wir auf den Lock gewartet haben.
		if cached, ok := successfulJWKS.Load(jwksURL); ok {
			if set, ok := cached.(jwk.Set); ok &&
				set != nil &&
				set.Len() > 0 {

				remoteSet = set
			}
		}

		if remoteSet == nil {

			// ----------------------------------------------------
			// URL registrieren
			// ----------------------------------------------------
			if !jwksCache.IsRegistered(jwksURL) {
				err := jwksCache.Register(
					jwksURL,
					jwk.WithRefreshInterval(15*time.Minute),
				)
				if err != nil {
					jwksCacheMutex.Unlock()

					return nil, fmt.Errorf(
						"failed to register JWKS URL %q: %w",
						jwksURL,
						err,
					)
				}
			}

			var lastErr error

			// ----------------------------------------------------
			// Maximal 10 Versuche.
			//
			// Refresh statt Get, damit tatsächlich erneut
			// geladen wird und nicht ein fehlerhafter Cache-State
			// wiederverwendet wird.
			// ----------------------------------------------------
			for attempt := 1; attempt <= maxJWKSFetchAttempts; attempt++ {

				time.Sleep(time.Second * 2)
				set, err := jwksCache.Refresh(
					r.Context(),
					jwksURL,
				)

				if err != nil {
					lastErr = err

					logrus.WithFields(logrus.Fields{
						"jwks_url": jwksURL,
						"attempt":  attempt,
						"max":      maxJWKSFetchAttempts,
					}).WithError(err).Warn(
						"failed to fetch JWKS",
					)

					continue
				}

				// HTTP 200 mit z.B.
				//
				// {"keys":[]}
				//
				// soll NICHT als erfolgreicher Fetch gelten.
				if set == nil {
					lastErr = errors.New(
						"JWKS endpoint returned nil key set",
					)

					continue
				}

				if set.Len() == 0 {
					lastErr = errors.New(
						"JWKS endpoint returned empty key set",
					)

					logrus.WithFields(logrus.Fields{
						"jwks_url": jwksURL,
						"attempt":  attempt,
						"max":      maxJWKSFetchAttempts,
					}).Warn(
						"JWKS endpoint returned empty key set",
					)

					continue
				}

				// ------------------------------------------------
				// Erfolg.
				//
				// Ab jetzt wird für diese URL nie wieder gefetcht.
				// ------------------------------------------------
				remoteSet = set
				successfulJWKS.Store(jwksURL, set)

				logrus.WithFields(logrus.Fields{
					"jwks_url": jwksURL,
					"attempt":  attempt,
					"keys":     set.Len(),
				}).Debug(
					"successfully fetched and cached JWKS",
				)

				break
			}

			// ----------------------------------------------------
			// Nach 10 Versuchen immer noch kein brauchbares Set.
			// ----------------------------------------------------
			if remoteSet == nil {

				unregisterErr := jwksCache.Unregister(jwksURL)

				jwksCacheMutex.Unlock()

				if unregisterErr != nil {
					return nil, fmt.Errorf(
						"failed to load JWKS from %q after %d attempts: %w; additionally failed to unregister JWKS URL: %v",
						jwksURL,
						maxJWKSFetchAttempts,
						lastErr,
						unregisterErr,
					)
				}

				return nil, fmt.Errorf(
					"failed to load JWKS from %q after %d attempts: %w",
					jwksURL,
					maxJWKSFetchAttempts,
					lastErr,
				)
			}
		}

		jwksCacheMutex.Unlock()
	}

	// ------------------------------------------------------------
	// 3. Andere lokale Fetcher hinzufügen
	// ------------------------------------------------------------
	var sets []jwk.Set

	for _, fetcher := range fetchers {
		keys, err := fetcher.GetKeys()
		if err != nil {
			logrus.Error(err)
			continue
		}

		if keys != nil {
			sets = append(sets, keys)
		}
	}

	sets = append(sets, remoteSet)

	keySetOption := ljwt.WithKeySet(
		CombineJwksSets(sets, r.Context()),
	)

	options = append(options, keySetOption)

	return ljwt.ParseRequest(r, options...)
}

func EncryptJweMessage(payload []byte, alg jwa.KeyAlgorithm, receipientKeys ...jwk.Key) *jwe.Message {
	options := []jwe.EncryptOption{jwe.WithJSON()}
	for _, key := range receipientKeys {
		var pubKey interface{}
		err := key.Raw(&pubKey)
		if err != nil {
			logrus.Error(err)
			return nil
		}
		options = append(options, jwe.WithKey(alg, pubKey))
	}
	encrypted, err := jwe.Encrypt([]byte(payload), options...)
	if err != nil {
		logrus.Errorf("failed to encrypt payload: %s\n", err)
		return nil
	}
	msg := jwe.NewMessage()
	msg.UnmarshalJSON(encrypted)
	return msg
}

func DecryptJweMessage(msg *jwe.Message, options ...jwe.DecryptOption) ([]byte, error) {
	if len(options) == 0 {
		return nil, errors.New("No Options for decryption set. Set at least WithKey or WithProvider")
	}

	payload, err := msg.MarshalJSON()

	if err != nil {
		logrus.Errorf("failed to marshal payload: %s\n", err)
		return nil, err
	}

	decrypted, err := jwe.Decrypt(payload, options...)
	if err != nil {
		logrus.Errorf("failed to decrypt payload: %s\n", err)
		return nil, err
	}
	return decrypted, nil
}
