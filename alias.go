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
	"errors"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/golang/protobuf/proto"
	"time"
)

const (
	ALIAS = "Alias"
)

func OpenAliasChannel() (*bcgo.Channel, error) {
	return bcgo.OpenChannel(ALIAS)
}

func UniqueAlias(a *bcgo.Channel, alias string) error {
	b := a.HeadBlock
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
					return errors.New("Alias already registered")
				}
			}
		}
		h := b.Previous
		if h != nil && len(h) > 0 {
			var err error
			b, err = bcgo.ReadBlockFile(a.Cache, h)
			if err != nil {
				return err
			}
		} else {
			b = nil
		}
	}
	return nil
}

func GetAlias(a *bcgo.Channel, publicKey *rsa.PublicKey) (string, error) {
	b := a.HeadBlock
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
			var err error
			b, err = bcgo.ReadBlockFile(a.Cache, h)
			if err != nil {
				return "", err
			}
		} else {
			b = nil
		}
	}
	return "", errors.New("Could not find alias for public key")
}

func GetPublicKey(a *bcgo.Channel, alias string) (*rsa.PublicKey, error) {
	b := a.HeadBlock
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
			var err error
			b, err = bcgo.ReadBlockFile(a.Cache, h)
			if err != nil {
				return nil, err
			}
		} else {
			b = nil
		}
	}
	return nil, errors.New("Could not find public key for alias")
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
