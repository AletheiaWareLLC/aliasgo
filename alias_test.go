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
	"fmt"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/testinggo"
	"testing"
)

// TODO split/move
func makeAlias(t *testing.T, cache bcgo.Cache, alias string, previousHash []byte, previousBlock *bcgo.Block) (*rsa.PrivateKey, []byte, *bcgo.Block, *bcgo.Record) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	testinggo.AssertNoError(t, err)

	record, err := aliasgo.CreateSignedAliasRecord(alias, privateKey)
	testinggo.AssertNoError(t, err)

	recordHash, err := bcgo.HashProtobuf(record)
	testinggo.AssertNoError(t, err)

	block := &bcgo.Block{
		Entry: []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				Record:     record,
				RecordHash: recordHash,
			},
		},
	}

	if previousHash != nil {
		block.Previous = previousHash
		if previousBlock != nil {
			block.Length = previousBlock.Length + 1
		}
	}

	blockHash, err := bcgo.HashProtobuf(block)
	testinggo.AssertNoError(t, err)

	headReference := &bcgo.Reference{
		ChannelName: aliasgo.ALIAS,
		BlockHash:   blockHash,
	}

	err = cache.PutHead(aliasgo.ALIAS, headReference)
	testinggo.AssertNoError(t, err)

	err = cache.PutBlock(blockHash, block)
	testinggo.AssertNoError(t, err)

	return privateKey, blockHash, block, record
}

func TestAliasUnique(t *testing.T) {
	t.Run("Unique", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		err := channel.UniqueAlias(cache, "Alice")
		if err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
	})
	t.Run("NotUnique", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		makeAlias(t, cache, "Alice", nil, nil)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		err := channel.UniqueAlias(cache, "Alice")
		if err == nil || err.Error() != fmt.Sprintf(aliasgo.ERROR_ALIAS_ALREADY_REGISTERED, "Alice") {
			t.Fatalf("Expected error, got '%s'", err)
		}
	})
}

func TestAliasGetAlias(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		aliceKey, _, _, _ := makeAlias(t, cache, "Alice", nil, nil)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		alias, err := channel.GetAlias(cache, &aliceKey.PublicKey)
		if err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		if alias.Alias != "Alice" {
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
		_, err = channel.GetAlias(cache, &privateKey.PublicKey)
		if err == nil || err.Error() != aliasgo.ERROR_ALIAS_NOT_FOUND {
			t.Fatalf("Expected error, got '%s'", err)
		}
	})
}

func TestAliasGetPublicKey(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		aliceKey, _, _, _ := makeAlias(t, cache, "Alice", nil, nil)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		key, err := channel.GetPublicKey(cache, "Alice")
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
		_, err := channel.GetPublicKey(cache, "Alice")
		if err == nil || err.Error() != aliasgo.ERROR_PUBLIC_KEY_NOT_FOUND {
			t.Fatalf("Expected error, got '%s'", err)
		}
	})
}

func TestAliasGetAliasRecord(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		aliceKey, _, _, aliceRecord := makeAlias(t, cache, "Alice", nil, nil)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		record, alias, err := channel.GetRecord(cache, "Alice")
		if err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		if record.String() != aliceRecord.String() {
			t.Fatalf("Incorrect record; expected '%s', got '%s'", aliceRecord.String(), record.String())
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
		_, _, err := channel.GetRecord(cache, "Alice")
		if err == nil || err.Error() != aliasgo.ERROR_ALIAS_NOT_FOUND {
			t.Fatalf("Expected error, got '%s'", err)
		}
	})
}

func TestAliasValidate(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		_, aliceHash, aliceBlock, _ := makeAlias(t, cache, "Alice", nil, nil)
		_, bobHash, bobBlock, _ := makeAlias(t, cache, "Bob", aliceHash, aliceBlock)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		channel.Threshold = 0 // Make it easy
		err := channel.Validate(cache, aliceHash, aliceBlock)
		if err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		err = channel.Validate(cache, bobHash, bobBlock)
		if err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
	})
	t.Run("NotValid", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(1)
		_, aliceHash1, aliceBlock1, _ := makeAlias(t, cache, "Alice", nil, nil)
		_, aliceHash2, aliceBlock2, _ := makeAlias(t, cache, "Alice", aliceHash1, aliceBlock1)
		channel := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		channel.Threshold = 0 // Make it easy
		err := channel.Validate(cache, aliceHash1, aliceBlock1)
		if err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		err = channel.Validate(cache, aliceHash2, aliceBlock2)
		if err == nil || err.Error() != fmt.Sprintf(aliasgo.ERROR_ALIAS_ALREADY_REGISTERED, "Alice") {
			t.Fatalf("Expected error, got '%s'", err)
		}
	})
}

// TODO TestCreateAliasRecord
// TODO TestRegisterAlias