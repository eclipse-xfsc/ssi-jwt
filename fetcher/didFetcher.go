package fetcher

import (
	"context"
	"time"

	"github.com/eclipse-xfsc/did-core/v2"
	"github.com/eclipse-xfsc/did-core/v2/types"
	jwt "github.com/eclipse-xfsc/ssi-jwt/v2"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/madflojo/tasks"
	"github.com/sirupsen/logrus"
)

type DidFetcher struct {
	dids          []string
	initialized   bool
	taskScheduler *tasks.Scheduler
	docs          map[string]interface{}
}

func (fetcher *DidFetcher) Initialize(dids []string, interval time.Duration) error {
	// Start the Scheduler
	fetcher.taskScheduler = tasks.New()
	fetcher.dids = dids
	err := fetcher.GetDidDocs()

	if err != nil {
		return err
	}
	// Add a task
	_, err = fetcher.taskScheduler.Add(&tasks.Task{
		Interval: interval,
		TaskFunc: func() error {
			return fetcher.GetDidDocs()
		},
	})
	if err != nil {
		logrus.Fatal("Can create did fetcher sheduler")
	}

	fetcher.initialized = true
	return nil
}

func (fetcher *DidFetcher) GetDidDocs() error {
	fetcher.docs = make(map[string]interface{})
	for _, didString := range fetcher.dids {
		document, err := did.Resolve(didString)

		if err != nil {
			logrus.Error("DID " + didString + " cant be resolved. Keys NOT ADDED")
		}
		fetcher.docs[didString] = document
	}

	return nil
}

func (fetcher *DidFetcher) GetKeys() (jwk.Set, error) {
	var sets []jwk.Set
	for _, doc := range fetcher.docs {
		document := doc.(*types.DidDocument)
		sets = append(sets, document.GetPublicKeys())
	}
	return jwt.CombineJwksSets(sets, context.Background()), nil
}

func (fetcher *DidFetcher) Stop() {
	fetcher.taskScheduler.Stop()
}
