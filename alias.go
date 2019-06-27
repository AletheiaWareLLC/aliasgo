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
	"fmt"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/golang/protobuf/proto"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	ALIAS = "Alias"

	MAX_ALIAS_LENGTH = 100

	ERROR_ALIAS_ALREADY_REGISTERED = "Alias already registered: %s"
	ERROR_ALIAS_NOT_FOUND          = "Could not find alias for public key"
	ERROR_PUBLIC_KEY_NOT_FOUND     = "Could not find public key for alias"
	ERROR_ALIAS_TOO_LONG           = "Alias too long: %d max: %d"
)

type AliasChannel struct {
	Name      string
	Threshold uint64
	HeadHash  []byte
	Timestamp uint64
}

func OpenAliasChannel() *AliasChannel {
	return &AliasChannel{
		Name:      ALIAS,
		Threshold: bcgo.THRESHOLD_STANDARD,
	}
}

func (a *AliasChannel) GetName() string {
	return a.Name
}

func (a *AliasChannel) GetThreshold() uint64 {
	return a.Threshold
}

func (a *AliasChannel) String() string {
	return a.Name + " " + strconv.FormatUint(a.Threshold, 10)
}

func (a *AliasChannel) Validate(cache bcgo.Cache, network bcgo.Network, hash []byte, block *bcgo.Block) error {
	register := make(map[string]bool)
	return bcgo.Iterate(a.Name, hash, block, cache, network, func(h []byte, b *bcgo.Block) error {
		// Check hash ones pass threshold
		ones := bcgo.Ones(h)
		if ones < a.Threshold {
			return errors.New(fmt.Sprintf(bcgo.ERROR_HASH_TOO_WEAK, ones, a.Threshold))
		}
		for _, entry := range b.Entry {
			record := entry.Record
			// TODO Check record is public (no acl)
			a := &Alias{}
			err := proto.Unmarshal(record.Payload, a)
			if err != nil {
				return err
			}
			length := len(a.Alias)
			if length > MAX_ALIAS_LENGTH {
				return errors.New(fmt.Sprintf(ERROR_ALIAS_TOO_LONG, length, MAX_ALIAS_LENGTH))
			}
			v, exists := register[a.Alias]
			if exists || v {
				return errors.New(fmt.Sprintf(ERROR_ALIAS_ALREADY_REGISTERED, a.Alias))
			}
			fmt.Printf("Validated '%s'\n", a.Alias)
			register[a.Alias] = true
		}
		return nil
	})
}

func (a *AliasChannel) GetHead() []byte {
	return a.HeadHash
}

func (a *AliasChannel) SetHead(hash []byte) {
	a.HeadHash = hash
}

func (a *AliasChannel) GetTimestamp() uint64 {
	return a.Timestamp
}

func (a *AliasChannel) SetTimestamp(Timestamp uint64) {
	a.Timestamp = Timestamp
}

func (a *AliasChannel) UniqueAlias(cache bcgo.Cache, network bcgo.Network, alias string) error {
	return bcgo.Iterate(a.Name, a.GetHead(), nil, cache, network, func(hash []byte, block *bcgo.Block) error {
		for _, entry := range block.Entry {
			record := entry.Record
			if record.Creator == alias {
				a := &Alias{}
				err := proto.Unmarshal(record.Payload, a)
				if err != nil {
					return err
				}
				if a.Alias == alias {
					return errors.New(fmt.Sprintf(ERROR_ALIAS_ALREADY_REGISTERED, alias))
				}
			}
		}
		return nil
	})
}

func (a *AliasChannel) GetAlias(cache bcgo.Cache, network bcgo.Network, publicKey *rsa.PublicKey) (*Alias, error) {
	var result *Alias
	if err := bcgo.Iterate(a.Name, a.GetHead(), nil, cache, network, func(hash []byte, block *bcgo.Block) error {
		for _, entry := range block.Entry {
			record := entry.Record
			a := &Alias{}
			err := proto.Unmarshal(record.Payload, a)
			if err != nil {
				return err
			}
			pk, err := bcgo.ParseRSAPublicKey(a.PublicKey, a.PublicFormat)
			if err != nil {
				return err
			}
			if publicKey.N.Cmp(pk.N) == 0 && publicKey.E == pk.E {
				result = a
				return bcgo.StopIterationError{}
			}
		}
		return nil
	}); err != nil {
		switch err.(type) {
		case bcgo.StopIterationError:
			// Do nothing
			break
		default:
			return nil, err
		}
	}
	if result == nil {
		return nil, errors.New(ERROR_ALIAS_NOT_FOUND)
	}
	return result, nil
}

func (a *AliasChannel) GetPublicKey(cache bcgo.Cache, network bcgo.Network, alias string) (*rsa.PublicKey, error) {
	var result *rsa.PublicKey
	if err := bcgo.Iterate(a.Name, a.GetHead(), nil, cache, network, func(hash []byte, block *bcgo.Block) error {
		for _, entry := range block.Entry {
			record := entry.Record
			a := &Alias{}
			err := proto.Unmarshal(record.Payload, a)
			if err != nil {
				return err
			}
			if a.Alias == alias {
				result, err = bcgo.ParseRSAPublicKey(a.PublicKey, a.PublicFormat)
				if err != nil {
					return err
				}
				return bcgo.StopIterationError{}
			}
		}
		return nil
	}); err != nil {
		switch err.(type) {
		case bcgo.StopIterationError:
			// Do nothing
			break
		default:
			return nil, err
		}
	}
	if result == nil {
		return nil, errors.New(ERROR_PUBLIC_KEY_NOT_FOUND)
	}
	return result, nil
}

func (a *AliasChannel) GetRecord(cache bcgo.Cache, network bcgo.Network, alias string) (*bcgo.Record, *Alias, error) {
	var recordResult *bcgo.Record
	var aliasResult *Alias
	if err := bcgo.Iterate(a.Name, a.GetHead(), nil, cache, network, func(hash []byte, block *bcgo.Block) error {
		for _, entry := range block.Entry {
			record := entry.Record
			if record.Creator == alias {
				recordResult = record
				aliasResult = &Alias{}
				err := proto.Unmarshal(record.Payload, aliasResult)
				if err != nil {
					return err
				}
				return bcgo.StopIterationError{}
			}
		}
		return nil
	}); err != nil {
		switch err.(type) {
		case bcgo.StopIterationError:
			// Do nothing
			break
		default:
			return nil, nil, err
		}
	}
	if recordResult == nil || aliasResult == nil {
		return nil, nil, errors.New(ERROR_ALIAS_NOT_FOUND)
	}
	return recordResult, aliasResult, nil
}

func CreateSignedAliasRecord(alias string, privateKey *rsa.PrivateKey) (*bcgo.Record, error) {
	length := len(alias)
	if length > MAX_ALIAS_LENGTH {
		return nil, errors.New(fmt.Sprintf(ERROR_ALIAS_TOO_LONG, length, MAX_ALIAS_LENGTH))
	}

	publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	publicKeyFormat := bcgo.PublicKeyFormat_PKIX
	hash, err := bcgo.HashProtobuf(&Alias{
		Alias:        alias,
		PublicKey:    publicKeyBytes,
		PublicFormat: publicKeyFormat,
	})
	if err != nil {
		return nil, err
	}

	signatureAlgorithm := bcgo.SignatureAlgorithm_SHA512WITHRSA_PSS
	signature, err := bcgo.CreateSignature(privateKey, hash, signatureAlgorithm)
	if err != nil {
		return nil, err
	}

	return CreateAliasRecord(alias, publicKeyBytes, publicKeyFormat, signature, signatureAlgorithm)
}

func CreateAliasRecord(alias string, publicKey []byte, publicKeyFormat bcgo.PublicKeyFormat, signature []byte, signatureAlgorithm bcgo.SignatureAlgorithm) (*bcgo.Record, error) {
	length := len(alias)
	if length > MAX_ALIAS_LENGTH {
		return nil, errors.New(fmt.Sprintf(ERROR_ALIAS_TOO_LONG, length, MAX_ALIAS_LENGTH))
	}

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
	length := len(alias)
	if length > MAX_ALIAS_LENGTH {
		return errors.New(fmt.Sprintf(ERROR_ALIAS_TOO_LONG, length, MAX_ALIAS_LENGTH))
	}

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
