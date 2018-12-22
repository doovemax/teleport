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
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

// Cache implements auth.AccessPoint interface and remembers
// the previously returned upstream value for each API call.
//
// This which can be used if the upstream AccessPoint goes offline
type Cache struct {
	sync.RWMutex
	Config
	*log.Entry
	ctx        context.Context
	cancel     context.CancelFunc
	trustCache services.Trust
}

// Config is Cache config
type Config struct {
	// Context is context for parent operations
	Context context.Context
	// Events provides events watchers
	Events services.Events
	// Trust is a service providing information about certificate
	// authorities
	Trust services.Trust
	// Backend is a backend for local cache
	Backend backend.Backend
	// RetryPeriod is a period between cache retries on failures
	RetryPeriod time.Duration
	// EventsC is a channel for event notifications,
	// used in tests
	EventsC chan CacheEvent
}

// CheckAndSetDefaults checks parameters and sets default values
func (c *Config) CheckAndSetDefaults() error {
	if c.Context == nil {
		c.Context = context.Background()
	}
	if c.Events == nil {
		return trace.BadParameter("missing Events parameter")
	}
	if c.Trust == nil {
		return trace.BadParameter("missing Trust parameter")
	}
	if c.Backend == nil {
		return trace.BadParameter("missing Backend parameter")
	}
	if c.RetryPeriod == 0 {
		c.RetryPeriod = defaults.HighResPollingPeriod
	}
	return nil
}

// CacheEvent is event used in tests
type CacheEvent struct {
	// Type is event type
	Type string
	// Event is event processed
	// by the event cycle
	Event services.Event
}

const (
	// EventProcessed is emitted whenever event is processed
	EventProcessed = "event_processed"
	// WatcherStarted is emitted when a new event watcher is started
	WatcherStarted = "watcher_started"
)

// New creates a new instance of Cache
func New(config Config) (*Cache, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	ctx, cancel := context.WithCancel(config.Context)
	cs := &Cache{
		ctx:        ctx,
		cancel:     cancel,
		Config:     config,
		trustCache: local.NewCAService(config.Backend),
		Entry: log.WithFields(log.Fields{
			trace.Component: teleport.ComponentCachingClient,
		}),
	}
	_, err := cs.fetch()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	go cs.update()
	return cs, nil
}

// instance is a cache instance,
type instance struct {
	parent *Cache
	services.Trust
}

func (c *Cache) update() {
	t := time.NewTicker(c.RetryPeriod)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-c.ctx.Done():
			return
		}
		err := c.fetchAndWatch()
		if err != nil {
			c.Warningf("Going to re-init the cache because of the error: %v.", err)
		}
	}
}

func (c *Cache) notify(event CacheEvent) {
	if c.EventsC == nil {
		return
	}
	select {
	case c.EventsC <- event:
		return
	case <-c.ctx.Done():
		return
	}
}

func (c *Cache) fetch() (int64, error) {
	id1, err := c.updateCertAuthorities(services.HostCA)
	if err != nil {
		return -1, trace.Wrap(err)
	}
	id2, err := c.updateCertAuthorities(services.UserCA)
	if err != nil {
		return -1, trace.Wrap(err)
	}
	return max(id1, id2), nil
}

func (c *Cache) fetchAndWatch() error {
	resourceID, err := c.fetch()
	if err != nil {
		return trace.Wrap(err)
	}
	watcher, err := c.Events.NewWatcher(c.ctx, services.Watch{Kinds: []string{services.KindCertAuthority}})
	if err != nil {
		return trace.Wrap(err)
	}
	defer watcher.Close()
	c.notify(CacheEvent{Type: WatcherStarted})
updateloop:
	for {
		select {
		case <-watcher.Done():
			if err != nil {
				return trace.Wrap(watcher.Error())
			}
			return trace.ConnectionProblem(nil, "unexpected watcher close")
		case <-c.ctx.Done():
			return trace.ConnectionProblem(c.ctx.Err(), "context is closing")
		case event := <-watcher.Events():
			if event.Resource.GetResourceID() < resourceID {
				c.Debugf("Skipping obsolete event %v %v.", event.Resource.GetResourceID(), event.Resource)
				continue updateloop
			}
			switch event.Type {
			case backend.OpDelete:
				switch event.Resource.GetKind() {
				case services.KindCertAuthority:
					err := c.trustCache.DeleteCertAuthority(services.CertAuthID{
						Type:       services.CertAuthType(event.Resource.GetSubKind()),
						DomainName: event.Resource.GetName(),
					})
					if err != nil {
						c.Warningf("Failed to delete cert authority %v.", err)
						return trace.Wrap(err)
					}
					c.notify(CacheEvent{Event: event, Type: EventProcessed})
				default:
					c.Debugf("Skipping unsupported resource %v", event.Resource.GetKind())
				}
			case backend.OpPut:
				switch resource := event.Resource.(type) {
				case services.CertAuthority:
					if err := c.trustCache.UpsertCertAuthority(resource); err != nil {
						return trace.Wrap(err)
					}
					c.notify(CacheEvent{Event: event, Type: EventProcessed})
				}
			default:
				c.Warningf("Skipping unsupported event type %v.", event.Type)
			}
		}
	}
}

func (c *Cache) updateCertAuthorities(caType services.CertAuthType) (int64, error) {
	authorities, err := c.Trust.GetCertAuthorities(caType, false, services.SkipValidation())
	if err != nil {
		return -1, trace.Wrap(err)
	}
	c.Debugf("Got cert authorities: %v %v.", caType, authorities)
	if err := c.trustCache.DeleteAllCertAuthorities(caType); err != nil {
		if !trace.IsNotFound(err) {
			return -1, trace.Wrap(err)
		}
	}
	var resourceID int64
	for _, ca := range authorities {
		if ca.GetResourceID() > resourceID {
			resourceID = ca.GetResourceID()
		}
		if err := c.trustCache.UpsertCertAuthority(ca); err != nil {
			return -1, trace.Wrap(err)
		}
	}
	return resourceID, nil
}

// GetCertAuthority returns certificate authority by given id. Parameter loadSigningKeys
// controls if signing keys are loaded
func (c *Cache) GetCertAuthority(id services.CertAuthID, loadSigningKeys bool, opts ...services.MarshalOption) (services.CertAuthority, error) {
	return c.trustCache.GetCertAuthority(id, loadSigningKeys, opts...)
}

// GetCertAuthorities returns a list of authorities of a given type
// loadSigningKeys controls whether signing keys should be loaded or not
func (c *Cache) GetCertAuthorities(caType services.CertAuthType, loadSigningKeys bool, opts ...services.MarshalOption) ([]services.CertAuthority, error) {
	return c.trustCache.GetCertAuthorities(caType, loadSigningKeys, opts...)
}

func max(v ...int64) int64 {
	var m int64
	for _, i := range v {
		if i > m {
			m = i
		}
	}
	return m
}
