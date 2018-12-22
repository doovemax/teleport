/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/lib/services/suite"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
	"gopkg.in/check.v1"
)

type CacheSuite struct {
	dataDir string
	backend backend.Backend
	clock   clockwork.Clock
}

var _ = check.Suite(&CacheSuite{})

// bootstrap check
func TestState(t *testing.T) { check.TestingT(t) }

func (s *CacheSuite) SetUpSuite(c *check.C) {
	utils.InitLoggerForTests(testing.Verbose())
	s.clock = clockwork.NewRealClock()
}

func (s *CacheSuite) SetUpTest(c *check.C) {
	// create a new auth server:
	s.dataDir = c.MkDir()
	var err error
	s.backend, err = lite.NewWithConfig(context.TODO(), lite.Config{Path: s.dataDir, PollStreamPeriod: 200 * time.Millisecond})
	c.Assert(err, check.IsNil)
}

func (s *CacheSuite) TearDownTest(c *check.C) {
	s.backend.Close()
}

// TestCA tests certificate authorities
func (s *CacheSuite) TestCA(c *check.C) {
	cacheDir := c.MkDir()
	cacheBackend, err := lite.NewWithConfig(context.TODO(), lite.Config{Path: cacheDir, EventsOff: true})
	c.Assert(err, check.IsNil)

	eventsC := make(chan CacheEvent, 100)
	ctx := context.TODO()
	c.Assert(err, check.IsNil)
	trust := local.NewCAService(s.backend)
	clt, err := New(Config{
		Context:     ctx,
		Backend:     cacheBackend,
		Events:      local.NewEventsService(s.backend),
		Trust:       trust,
		RetryPeriod: 200 * time.Millisecond,
		EventsC:     eventsC,
	})
	c.Assert(err, check.IsNil)
	c.Assert(clt, check.NotNil)

	select {
	case <-eventsC:
	case <-time.After(time.Second):
		c.Fatalf("wait for the watcher to start")
	}

	ca := suite.NewTestCA(services.UserCA, "example.com")
	c.Assert(trust.UpsertCertAuthority(ca), check.IsNil)

	select {
	case <-eventsC:
	case <-time.After(time.Second):
		c.Fatalf("timeout waiting for event")
	}

	out, err := clt.GetCertAuthority(ca.GetID(), false)
	c.Assert(err, check.IsNil)
	ca.SetResourceID(out.GetResourceID())
	services.RemoveCASecrets(ca)
	fixtures.DeepCompare(c, ca, out)

	err = trust.DeleteCertAuthority(ca.GetID())
	c.Assert(err, check.IsNil)

	select {
	case <-eventsC:
	case <-time.After(time.Second):
		c.Fatalf("timeout waiting for event")
	}

	_, err = clt.GetCertAuthority(ca.GetID(), false)
	fixtures.ExpectNotFound(c, err)
}

// TestRecovery tests error recovery scenario
func (s *CacheSuite) TestRecovery(c *check.C) {
	cacheDir := c.MkDir()
	cacheBackend, err := lite.NewWithConfig(context.TODO(), lite.Config{Path: cacheDir, EventsOff: true})
	c.Assert(err, check.IsNil)

	eventsC := make(chan CacheEvent, 100)
	ctx := context.TODO()
	c.Assert(err, check.IsNil)
	trust := local.NewCAService(s.backend)
	events := &proxyEvents{events: local.NewEventsService(s.backend)}
	clt, err := New(Config{
		Context:     ctx,
		Backend:     cacheBackend,
		Events:      events,
		Trust:       trust,
		RetryPeriod: 200 * time.Millisecond,
		EventsC:     eventsC,
	})
	c.Assert(err, check.IsNil)
	c.Assert(clt, check.NotNil)

	select {
	case <-eventsC:
	case <-time.After(time.Second):
		c.Fatalf("wait for the watcher to start")
	}

	ca := suite.NewTestCA(services.UserCA, "example.com")
	c.Assert(trust.UpsertCertAuthority(ca), check.IsNil)

	select {
	case <-eventsC:
	case <-time.After(time.Second):
		c.Fatalf("timeout waiting for event")
	}

	// event has arrived, now close the watchers
	watchers := events.getWatchers()
	c.Assert(watchers, check.HasLen, 1)
	events.closeWatchers()

	// add modification and expect the resource to recover
	ca2 := suite.NewTestCA(services.UserCA, "example2.com")
	c.Assert(trust.UpsertCertAuthority(ca2), check.IsNil)

	authorities, err := trust.GetCertAuthorities(services.UserCA, false, services.SkipValidation())
	c.Assert(err, check.IsNil)
	log.Debugf("Hardware appliance: %v", authorities)

	// wait for watcher to restart
	select {
	case event := <-eventsC:
		c.Assert(event.Type, check.Equals, WatcherStarted)
	case <-time.After(time.Second):
		c.Fatalf("timeout waiting for event")
	}

	out, err := clt.GetCertAuthority(ca2.GetID(), false)
	c.Assert(err, check.IsNil)
	ca2.SetResourceID(out.GetResourceID())
	services.RemoveCASecrets(ca2)
	fixtures.DeepCompare(c, ca2, out)
}

type proxyEvents struct {
	sync.Mutex
	watchers []services.Watcher
	events   services.Events
}

func (p *proxyEvents) getWatchers() []services.Watcher {
	p.Lock()
	defer p.Unlock()
	out := make([]services.Watcher, len(p.watchers))
	copy(out, p.watchers)
	return out
}

func (p *proxyEvents) closeWatchers() {
	p.Lock()
	defer p.Unlock()
	for i := range p.watchers {
		p.watchers[i].Close()
	}
	p.watchers = nil
	return
}

func (p *proxyEvents) NewWatcher(ctx context.Context, watch services.Watch) (services.Watcher, error) {
	w, err := p.events.NewWatcher(ctx, watch)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	p.Lock()
	defer p.Unlock()
	p.watchers = append(p.watchers, w)
	return w, nil
}
