package fetcher

import (
	"context"
	"errors"
	"time"

	jwt "github.com/eclipse-xfsc/ssi-jwt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/sirupsen/logrus"
)

type JwksFetcher struct {
	jwksUrls    []string
	cache       jwk.Cache
	initialized bool
}

func (fetcher *JwksFetcher) Initialize(jwksUrls []string, interval time.Duration) {

	fetcher.cache = *jwk.NewCache(context.Background(), jwk.WithRefreshWindow(interval))
	for _, url := range jwksUrls {
		fetcher.cache.Register(url)
	}
	fetcher.jwksUrls = jwksUrls
	fetcher.initialized = true
}

func (fetcher *JwksFetcher) GetKeys() (jwk.Set, error) {

	if !fetcher.initialized {
		return nil, errors.New("fetcher not initialized")
	}
	var sets []jwk.Set
	for _, url := range fetcher.jwksUrls {
		set, err := fetcher.cache.Get(context.Background(), url)
		if err == nil {
			sets = append(sets, set)
		} else {
			logrus.Error(err)
		}
	}
	return jwt.CombineJwksSets(sets, context.Background()), nil
}

func (fetcher *JwksFetcher) Stop() {

}
