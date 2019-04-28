/*
 * Copyright 2019 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package aliasgo

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/golang/protobuf/proto"
	"net/http"
	"net/url"
	"time"
)

const (
	ALIAS = "Alias"

	ERROR_ALIAS_ALREADY_REGISTERED = "Alias already registered"
	ERROR_ALIAS_NOT_FOUND          = "Could not find alias for public key"
	ERROR_PUBLIC_KEY_NOT_FOUND     = "Could not find public key for alias"
)

func OpenAndLoadAliasChannel(cache bcgo.Cache, network bcgo.Network) *bcgo.PoWChannel {
	return bcgo.OpenAndLoadPoWChannel(ALIAS, bcgo.THRESHOLD_STANDARD, cache, network)
}

func UniqueAlias(aliases bcgo.ThresholdChannel, cache bcgo.Cache, network bcgo.Network, alias string) error {
	head := aliases.GetHead()
	if head != nil {
		b, err := bcgo.GetBlock(ALIAS, cache, network, head)
		if err != nil {
			return err
		}
		for b != nil {
			for _, e := range b.Entry {
				r := e.Record
				if r.Creator == alias {
					a := &Alias{}
					err := proto.Unmarshal(r.Payload, a)
					if err != nil {
						return err
					}
					if a.Alias == alias {
						return errors.New(ERROR_ALIAS_ALREADY_REGISTERED)
					}
				}
			}
			h := b.Previous
			if h != nil && len(h) > 0 {
				b, err = bcgo.GetBlock(ALIAS, cache, network, h)
				if err != nil {
					return err
				}
			} else {
				b = nil
			}
		}
	}
	return nil
}

func GetAlias(aliases bcgo.ThresholdChannel, cache bcgo.Cache, network bcgo.Network, publicKey *rsa.PublicKey) (string, error) {
	head := aliases.GetHead()
	if head != nil {
		b, err := bcgo.GetBlock(ALIAS, cache, network, head)
		if err != nil {
			return "", err
		}
		for b != nil {
			for _, e := range b.Entry {
				r := e.Record
				a := &Alias{}
				err := proto.Unmarshal(r.Payload, a)
				if err != nil {
					return "", err
				}
				pk, err := bcgo.ParseRSAPublicKey(a.PublicKey, a.PublicFormat)
				if err != nil {
					return "", err
				}
				if publicKey.N.Cmp(pk.N) == 0 && publicKey.E == pk.E {
					return a.Alias, nil
				}
			}
			h := b.Previous
			if h != nil && len(h) > 0 {
				b, err = bcgo.GetBlock(ALIAS, cache, network, h)
				if err != nil {
					return "", err
				}
			} else {
				b = nil
			}
		}
	}
	return "", errors.New(ERROR_ALIAS_NOT_FOUND)
}

func GetPublicKey(aliases bcgo.ThresholdChannel, cache bcgo.Cache, network bcgo.Network, alias string) (*rsa.PublicKey, error) {
	head := aliases.GetHead()
	if head != nil {
		b, err := bcgo.GetBlock(ALIAS, cache, network, head)
		if err != nil {
			return nil, err
		}
		for b != nil {
			for _, e := range b.Entry {
				r := e.Record
				if r.Creator == alias {
					a := &Alias{}
					err := proto.Unmarshal(r.Payload, a)
					if err != nil {
						return nil, err
					}
					if a.Alias == alias {
						return bcgo.ParseRSAPublicKey(a.PublicKey, a.PublicFormat)
					}
				}
			}
			h := b.Previous
			if h != nil && len(h) > 0 {
				b, err = bcgo.GetBlock(ALIAS, cache, network, h)
				if err != nil {
					return nil, err
				}
			} else {
				b = nil
			}
		}
	}
	return nil, errors.New(ERROR_PUBLIC_KEY_NOT_FOUND)
}

func GetAliasRecord(aliases bcgo.ThresholdChannel, cache bcgo.Cache, network bcgo.Network, alias string) (*bcgo.Record, *Alias, error) {
	head := aliases.GetHead()
	if head != nil {
		b, err := bcgo.GetBlock(ALIAS, cache, network, head)
		if err != nil {
			return nil, nil, err
		}
		for b != nil {
			for _, e := range b.Entry {
				r := e.Record
				if r.Creator == alias {
					a := &Alias{}
					err := proto.Unmarshal(r.Payload, a)
					if err != nil {
						return nil, nil, err
					}
					if a.Alias == alias {
						return r, a, nil
					}
				}
			}
			h := b.Previous
			if h != nil && len(h) > 0 {
				b, err = bcgo.GetBlock(ALIAS, cache, network, h)
				if err != nil {
					return nil, nil, err
				}
			} else {
				b = nil
			}
		}
	}
	return nil, nil, errors.New(ERROR_ALIAS_NOT_FOUND)
}

func CreateAliasRecord(alias string, publicKey []byte, publicKeyFormat bcgo.PublicKeyFormat, signature []byte, signatureAlgorithm bcgo.SignatureAlgorithm) (*bcgo.Record, error) {
	pubKey, err := bcgo.ParseRSAPublicKey(publicKey, publicKeyFormat)
	if err != nil {
		return nil, err
	}

	a := &Alias{
		Alias:        alias,
		PublicKey:    publicKey,
		PublicFormat: publicKeyFormat,
	}
	data, err := proto.Marshal(a)
	if err != nil {
		return nil, err
	}

	if err := bcgo.VerifySignature(pubKey, bcgo.Hash(data), signature, signatureAlgorithm); err != nil {
		return nil, err
	}

	record := &bcgo.Record{
		Timestamp:           uint64(time.Now().UnixNano()),
		Creator:             alias,
		Payload:             data,
		EncryptionAlgorithm: bcgo.EncryptionAlgorithm_UNKNOWN_ENCRYPTION,
		Signature:           signature,
		SignatureAlgorithm:  signatureAlgorithm,
	}
	return record, nil
}

func RegisterAlias(host, alias string, key *rsa.PrivateKey) error {
	publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(&key.PublicKey)
	if err != nil {
		return err
	}

	data, err := proto.Marshal(&Alias{
		Alias:        alias,
		PublicKey:    publicKeyBytes,
		PublicFormat: bcgo.PublicKeyFormat_PKIX,
	})
	if err != nil {
		return err
	}

	signatureAlgorithm := bcgo.SignatureAlgorithm_SHA512WITHRSA_PSS

	signature, err := bcgo.CreateSignature(key, bcgo.Hash(data), signatureAlgorithm)
	if err != nil {
		return err
	}

	response, err := http.PostForm(host+"/alias-register", url.Values{
		"alias":              {alias},
		"publicKey":          {base64.RawURLEncoding.EncodeToString(publicKeyBytes)},
		"publicKeyFormat":    {"PKIX"},
		"signature":          {base64.RawURLEncoding.EncodeToString(signature)},
		"signatureAlgorithm": {signatureAlgorithm.String()},
	})
	if err != nil {
		return err
	}
	switch response.StatusCode {
	case http.StatusOK:
		return nil
	default:
		return errors.New("Registration status: " + response.Status)
	}
}
