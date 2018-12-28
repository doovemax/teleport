/*
Copyright 2015-2018 Gravitational, Inc.

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

package services

import (
	"fmt"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
)

// NewProvisionToken returns a new instance of provision token resource
func NewProvisionToken(token string, roles teleport.Roles, expires time.Time) (ProvisionToken, error) {
	t := &ProvisionTokenV2{
		Kind:    KindToken,
		Version: V2,
		Metadata: Metadata{
			Name:      token,
			Expires:   &expires,
			Namespace: defaults.Namespace,
		},
		Spec: ProvisionTokenSpecV2{
			Roles: roles,
		},
	}
	if err := t.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return t, nil
}

// Provisioner governs adding new nodes to the cluster
type Provisioner interface {
	// UpsertToken adds provisioning tokens for the auth server
	UpsertToken(ProvisionToken) error

	// GetToken finds and returns token by id
	GetToken(token string) (ProvisionToken, error)

	// DeleteToken deletes provisioning token
	DeleteToken(token string) error

	// GetTokens returns all non-expired tokens
	GetTokens() ([]ProvisionToken, error)
}

// ProvisionToken is a provisioning token
type ProvisionToken interface {
	Resource
	// GetRoles returns a list of teleport roles
	// that will be granted to the user of the token
	// in the crendentials
	GetRoles() teleport.Roles
	// SetRoles sets teleport roles
	SetRoles(teleport.Roles)
	// V1 returns V1 version of the resource
	V1() *ProvisionTokenV1
	// String returns user friendly representation of the resource
	String() string
	// CheckAndSetDefaults checks parameters and sets default values
	CheckAndSetDefaults() error
}

// CheckAndSetDefaults checks and set default values for any missing fields.
func (p *ProvisionTokenV2) CheckAndSetDefaults() error {
	p.Kind = KindToken
	err := p.Metadata.CheckAndSetDefaults()
	if err != nil {
		return trace.Wrap(err)
	}
	if len(p.Spec.Roles) == 0 {
		return trace.BadParameter("provisioning token is missing roles")
	}
	if err := teleport.Roles(p.Spec.Roles).Check(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// GetRoles returns a list of teleport roles
// that will be granted to the user of the token
// in the crendentials
func (p *ProvisionTokenV2) GetRoles() teleport.Roles {
	return p.Spec.Roles
}

// SetRoles sets teleport roles
func (p *ProvisionTokenV2) SetRoles(r teleport.Roles) {
	p.Spec.Roles = r
}

// GetKind returns resource kind
func (p *ProvisionTokenV2) GetKind() string {
	return p.Kind
}

// GetSubKind returns resource sub kind
func (p *ProvisionTokenV2) GetSubKind() string {
	return p.SubKind
}

// GetResourceID returns resource ID
func (p *ProvisionTokenV2) GetResourceID() int64 {
	return p.Metadata.ID
}

// SetResourceID sets resource ID
func (p *ProvisionTokenV2) SetResourceID(id int64) {
	p.Metadata.ID = id
}

// GetMetadata returns metadata
func (p *ProvisionTokenV2) GetMetadata() Metadata {
	return p.Metadata
}

// V1 returns V1 version of the resource
func (p *ProvisionTokenV2) V1() *ProvisionTokenV1 {
	return &ProvisionTokenV1{
		Roles:   p.Spec.Roles,
		Expires: p.Metadata.Expiry(),
		Token:   p.Metadata.Name,
	}
}

// V2 returns V2 version of the resource
func (p *ProvisionTokenV2) V2() *ProvisionTokenV2 {
	return p
}

// SetExpiry sets expiry time for the object
func (p *ProvisionTokenV2) SetExpiry(expires time.Time) {
	p.Metadata.SetExpiry(expires)
}

// Expires returns object expiry setting
func (s *ProvisionTokenV2) Expiry() time.Time {
	return s.Metadata.Expiry()
}

// SetTTL sets Expires header using realtime clock
func (p *ProvisionTokenV2) SetTTL(clock clockwork.Clock, ttl time.Duration) {
	p.Metadata.SetTTL(clock, ttl)
}

// GetName returns server name
func (p *ProvisionTokenV2) GetName() string {
	return p.Metadata.Name
}

// SetName sets the name of the TrustedCluster.
func (p *ProvisionTokenV2) SetName(e string) {
	p.Metadata.Name = e
}

// String returns the human readable representation of a provisioning token.
func (p ProvisionTokenV2) String() string {
	expires := "never"
	if !p.Expiry().IsZero() {
		expires = p.Expiry().String()
	}
	return fmt.Sprintf("ProvisionToken(Roles=%v, Expires=%v)", p.Spec.Roles, expires)
}

// ProvisionToken stores metadata about some provisioning token
type ProvisionTokenV1 struct {
	// Roles is a list of roles associated with the token,
	// that will be converted to metadata in the SSH and X509
	// certificates issued to the user of the token
	Roles teleport.Roles `json:"roles"`
	// Expires sets token expiry
	Expires time.Time `json:"expires"`
	// Token is a token name
	Token string `json:"token"`
}

// V1 returns V1 version of the resource
func (p *ProvisionTokenV1) V1() *ProvisionTokenV1 {
	return p
}

// V2 returns V2 version of the resource
func (p *ProvisionTokenV1) V2() *ProvisionTokenV2 {
	t := &ProvisionTokenV2{
		Kind:    KindToken,
		Version: V2,
		Metadata: Metadata{
			Name:      p.Token,
			Namespace: defaults.Namespace,
		},
		Spec: ProvisionTokenSpecV2{
			Roles: p.Roles,
		},
	}
	if !p.Expires.IsZero() {
		t.SetExpiry(p.Expires)
	}
	return t
}

// String returns the human readable representation of a provisioning token.
func (p ProvisionTokenV1) String() string {
	expires := "never"
	if p.Expires.Unix() != 0 {
		expires = p.Expires.String()
	}
	return fmt.Sprintf("ProvisionToken(Roles=%v, Expires=%v)",
		p.Roles, expires)
}

// ProvisionTokenSpecV2Schema is a JSON schema for provision token
const ProvisionTokenSpecV2Schema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "roles": {"type": "array", "items": {"type": "string"}}
  }
}`

// GetProvisionTokenSchema returns provision token schema
func GetProvisionTokenSchema() string {
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, ProvisionTokenSpecV2Schema, DefaultDefinitions)
}

// UnmarshalProvisionToken unmarshals provision token from JSON or YAML,
// sets defaults and checks the schema
func UnmarshalProvisionToken(data []byte, opts ...MarshalOption) (ProvisionToken, error) {
	if len(data) == 0 {
		return nil, trace.BadParameter("missing provision token data")
	}

	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var h ResourceHeader
	err = utils.FastUnmarshal(data, &h)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch h.Version {
	case "":
		var p ProvisionTokenV1
		err := utils.FastUnmarshal(data, &p)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return p.V2(), nil
	case V2:
		var p ProvisionTokenV2
		if cfg.SkipValidation {
			if err := utils.FastUnmarshal(data, &p); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		} else {
			if err := utils.UnmarshalWithSchema(GetProvisionTokenSchema(), &p, data); err != nil {
				return nil, trace.BadParameter(err.Error())
			}
		}

		if err := p.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}

		return &p, nil
	}
	return nil, trace.BadParameter("server resource version %v is not supported", h.Version)
}

// MarshalProvisionToken marshals provisioning token into JSON.
func MarshalProvisionToken(t ProvisionToken, opts ...MarshalOption) ([]byte, error) {
	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	type token1 interface {
		V1() *ProvisionTokenV1
	}
	type token2 interface {
		V2() *ProvisionTokenV2
	}
	version := cfg.GetVersion()
	switch version {
	case V1:
		v, ok := t.(token1)
		if !ok {
			return nil, trace.BadParameter("don't know how to marshal %v", V1)
		}
		return utils.FastMarshal(v.V1())
	case V2:
		v, ok := t.(token2)
		if !ok {
			return nil, trace.BadParameter("don't know how to marshal %v", V2)
		}
		return utils.FastMarshal(v.V2())
	default:
		return nil, trace.BadParameter("version %v is not supported", version)
	}
}
