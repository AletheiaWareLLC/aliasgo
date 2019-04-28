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

package aliasgo_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/golang/protobuf/proto"
	"testing"
)

// TODO split/move
func makeAlias(t *testing.T, channel *bcgo.PoWChannel, cache bcgo.Cache, alias string) *rsa.PrivateKey {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("Could not get private key: '%s'", err)
	}

	publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Could not convert public key: '%s'", err)
	}

	a := &aliasgo.Alias{
		Alias:        alias,
		PublicKey:    publicKeyBytes,
		PublicFormat: bcgo.PublicKeyFormat_PKIX,
	}

	payload, err := proto.Marshal(a)
	if err != nil {
		t.Fatalf("Could not marshal payload: '%s'", err)
	}
	record := &bcgo.Record{
		Creator: alias,
		Payload: payload,
	}
	recordHash, err := bcgo.HashProtobuf(record)
	if err != nil {
		t.Fatalf("Could not hash record: '%s'", err)
	}
	entries := []*bcgo.BlockEntry{
		&bcgo.BlockEntry{
			Record:     record,
			RecordHash: recordHash,
		},
	}
	block := &bcgo.Block{
		ChannelName: channel.GetName(),
		Entry:       entries,
	}
	blockHash, err := bcgo.HashProtobuf(block)
	if err != nil {
		t.Fatalf("Could not hash block: '%s'", err)
	}
	channel.Threshold = 1 // Make it easy
	if err := bcgo.Update(channel, cache, blockHash, block); err != nil {
		t.Fatalf("Could not update channel: '%s'", err)
	}
	return privateKey
}

func TestAliasUnique(t *testing.T) {
	t.Run("Unique", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		err := aliasgo.UniqueAlias(channel, cache, nil, "Alice")
		if err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
	})
	t.Run("NotUnique", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		makeAlias(t, channel, cache, "Alice")
		err := aliasgo.UniqueAlias(channel, cache, nil, "Alice")
		if err == nil || err.Error() != aliasgo.ERROR_ALIAS_ALREADY_REGISTERED {
			t.Fatalf("Expected error, got '%s'", err)
		}
	})
}

func TestAliasGetAlias(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		aliceKey := makeAlias(t, channel, cache, "Alice")
		alias, err := aliasgo.GetAlias(channel, cache, nil, &aliceKey.PublicKey)
		if err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		if alias != "Alice" {
			t.Fatalf("Incorrect alias; expected 'Alice', got '%s'", alias)
		}
	})
	t.Run("NotExists", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Fatalf("Could not get private key: '%s'", err)
		}
		_, err = aliasgo.GetAlias(channel, cache, nil, &privateKey.PublicKey)
		if err == nil || err.Error() != aliasgo.ERROR_ALIAS_NOT_FOUND {
			t.Fatalf("Expected error, got '%s'", err)
		}
	})
}

func TestAliasGetPublicKey(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		aliceKey := makeAlias(t, channel, cache, "Alice")
		key, err := aliasgo.GetPublicKey(channel, cache, nil, "Alice")
		if err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		keyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(key)
		if err != nil {
			t.Fatalf("Could not convert public key: '%s'", err)
		}
		publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(&aliceKey.PublicKey)
		if err != nil {
			t.Fatalf("Could not convert public key: '%s'", err)
		}
		if !bytes.Equal(keyBytes, publicKeyBytes) {
			t.Fatalf("Incorrect key; expected '%s', got '%s'", string(publicKeyBytes), string(keyBytes))
		}
	})
	t.Run("NotExists", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		_, err := aliasgo.GetPublicKey(channel, cache, nil, "Alice")
		if err == nil || err.Error() != aliasgo.ERROR_PUBLIC_KEY_NOT_FOUND {
			t.Fatalf("Expected error, got '%s'", err)
		}
	})
}

func TestAliasGetAliasRecord(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		aliceKey := makeAlias(t, channel, cache, "Alice")
		record, alias, err := aliasgo.GetAliasRecord(channel, cache, nil, "Alice")
		if err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		if record.Creator != "Alice" {
			t.Fatalf("Incorrect creator; expected Alice, got '%s'", record.Creator)
		}
		publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(&aliceKey.PublicKey)
		if err != nil {
			t.Fatalf("Could not convert public key: '%s'", err)
		}
		if !bytes.Equal(alias.PublicKey, publicKeyBytes) {
			t.Fatalf("Incorrect key; expected '%s', got '%s'", string(publicKeyBytes), string(alias.PublicKey))
		}
	})
	t.Run("NotExists", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		_, _, err := aliasgo.GetAliasRecord(channel, cache, nil, "Alice")
		if err == nil || err.Error() != aliasgo.ERROR_ALIAS_NOT_FOUND {
			t.Fatalf("Expected error, got '%s'", err)
		}
	})
}

// TODO TestCreateAliasRecord
// TODO TestRegisterAlias
