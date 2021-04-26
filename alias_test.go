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
	"aletheiaware.com/aliasgo"
	"aletheiaware.com/bcgo"
	"aletheiaware.com/bcgo/account"
	"aletheiaware.com/bcgo/cache"
	"aletheiaware.com/bcgo/channel"
	"aletheiaware.com/cryptogo"
	"aletheiaware.com/testinggo"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// TODO split/move
func makeAlias(t *testing.T, cache bcgo.Cache, alias string, previousHash []byte, previousBlock *bcgo.Block) (*rsa.PrivateKey, []byte, *bcgo.Block, *bcgo.Record) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	testinggo.AssertNoError(t, err)

	account := account.NewRSA(alias, privateKey)

	record, err := aliasgo.CreateSignedAliasRecord(account)
	testinggo.AssertNoError(t, err)

	recordHash, err := cryptogo.HashProtobuf(record)
	testinggo.AssertNoError(t, err)

	block := &bcgo.Block{
		Timestamp: 1,
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

	blockHash, err := cryptogo.HashProtobuf(block)
	testinggo.AssertNoError(t, err)

	headReference := &bcgo.Reference{
		Timestamp:   1,
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
		cache := cache.NewMemory(1)
		channel := aliasgo.OpenAliasChannel()
		if err := aliasgo.UniqueAlias(channel, cache, nil, "Alice"); err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
	})
	t.Run("NotUnique", func(t *testing.T) {
		cache := cache.NewMemory(1)
		makeAlias(t, cache, "Alice", nil, nil)
		channel := aliasgo.OpenAliasChannel()
		if err := channel.Load(cache, nil); err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		err := aliasgo.UniqueAlias(channel, cache, nil, "Alice")
		testinggo.AssertError(t, aliasgo.ErrAliasAlreadyRegistered{Alias: "Alice"}.Error(), err)
	})
}

func TestAliasAlias(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := cache.NewMemory(1)
		aliceKey, _, _, _ := makeAlias(t, cache, "Alice", nil, nil)
		channel := aliasgo.OpenAliasChannel()
		if err := channel.Load(cache, nil); err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		alias, err := aliasgo.AliasForKey(channel, cache, nil, &aliceKey.PublicKey)
		if err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		if alias.Alias != "Alice" {
			t.Fatalf("Incorrect alias; expected 'Alice', got '%s'", alias)
		}
	})
	t.Run("NotExists", func(t *testing.T) {
		cache := cache.NewMemory(1)
		channel := aliasgo.OpenAliasChannel()
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Fatalf("Could not get private key: '%s'", err)
		}
		_, err = aliasgo.AliasForKey(channel, cache, nil, &privateKey.PublicKey)
		testinggo.AssertError(t, aliasgo.ErrAliasNotFound{}.Error(), err)
	})
}

func TestAliasPublicKey(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := cache.NewMemory(1)
		aliceKey, _, _, _ := makeAlias(t, cache, "Alice", nil, nil)
		channel := aliasgo.OpenAliasChannel()
		if err := channel.Load(cache, nil); err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		key, err := aliasgo.PublicKeyForAlias(channel, cache, nil, "Alice")
		if err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		keyBytes, err := cryptogo.RSAPublicKeyToPKIXBytes(key)
		if err != nil {
			t.Fatalf("Could not convert public key: '%s'", err)
		}
		publicKeyBytes, err := cryptogo.RSAPublicKeyToPKIXBytes(&aliceKey.PublicKey)
		if err != nil {
			t.Fatalf("Could not convert public key: '%s'", err)
		}
		if !bytes.Equal(keyBytes, publicKeyBytes) {
			t.Fatalf("Incorrect key; expected '%s', got '%s'", string(publicKeyBytes), string(keyBytes))
		}
	})
	t.Run("NotExists", func(t *testing.T) {
		cache := cache.NewMemory(1)
		channel := aliasgo.OpenAliasChannel()
		_, err := aliasgo.PublicKeyForAlias(channel, cache, nil, "Alice")
		testinggo.AssertError(t, aliasgo.ErrPublicKeyNotFound{Alias: "Alice"}.Error(), err)
	})
}

func TestAliasAliasRecord(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := cache.NewMemory(1)
		aliceKey, _, _, aliceRecord := makeAlias(t, cache, "Alice", nil, nil)
		channel := aliasgo.OpenAliasChannel()
		if err := channel.Load(cache, nil); err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		record, alias, err := aliasgo.Record(channel, cache, nil, "Alice")
		if err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		if record.String() != aliceRecord.String() {
			t.Fatalf("Incorrect record; expected '%s', got '%s'", aliceRecord.String(), record.String())
		}
		publicKeyBytes, err := cryptogo.RSAPublicKeyToPKIXBytes(&aliceKey.PublicKey)
		if err != nil {
			t.Fatalf("Could not convert public key: '%s'", err)
		}
		if !bytes.Equal(alias.PublicKey, publicKeyBytes) {
			t.Fatalf("Incorrect key; expected '%s', got '%s'", string(publicKeyBytes), string(alias.PublicKey))
		}
	})
	t.Run("NotExists", func(t *testing.T) {
		cache := cache.NewMemory(1)
		channel := aliasgo.OpenAliasChannel()
		_, _, err := aliasgo.Record(channel, cache, nil, "Alice")
		testinggo.AssertError(t, aliasgo.ErrAliasNotFound{}.Error(), err)
	})
}

func TestAliasValidator(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		cache := cache.NewMemory(1)
		_, aliceHash, aliceBlock, _ := makeAlias(t, cache, "Alice", nil, nil)
		_, bobHash, bobBlock, _ := makeAlias(t, cache, "Bob", aliceHash, aliceBlock)
		channel := channel.New(aliasgo.ALIAS)
		if err := channel.Load(cache, nil); err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		validator := &aliasgo.AliasValidator{}
		if err := validator.Validate(channel, cache, nil, aliceHash, aliceBlock); err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		if err := validator.Validate(channel, cache, nil, bobHash, bobBlock); err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
	})
	t.Run("NotValid", func(t *testing.T) {
		cache := cache.NewMemory(1)
		_, aliceHash1, aliceBlock1, _ := makeAlias(t, cache, "Alice", nil, nil)
		_, aliceHash2, aliceBlock2, _ := makeAlias(t, cache, "Alice", aliceHash1, aliceBlock1)
		channel := channel.New(aliasgo.ALIAS)
		if err := channel.Load(cache, nil); err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		validator := &aliasgo.AliasValidator{}
		if err := validator.Validate(channel, cache, nil, aliceHash1, aliceBlock1); err != nil {
			t.Fatalf("Expected no error, got '%s'", err)
		}
		err := validator.Validate(channel, cache, nil, aliceHash2, aliceBlock2)
		testinggo.AssertError(t, aliasgo.ErrAliasAlreadyRegistered{Alias: "Alice"}.Error(), err)
	})
}

func TestAliasValidate(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		testinggo.AssertNoError(t, aliasgo.ValidateAlias("foobar"))
	})
	t.Run("NotValid_Space", func(t *testing.T) {
		testinggo.AssertError(t, aliasgo.ErrAliasInvalid{Alias: "foo bar"}.Error(), aliasgo.ValidateAlias("foo bar"))
	})
	t.Run("NotValid_Plus", func(t *testing.T) {
		testinggo.AssertError(t, aliasgo.ErrAliasInvalid{Alias: "foo+bar"}.Error(), aliasgo.ValidateAlias("foo+bar"))
	})
	t.Run("NotValid_Bracket", func(t *testing.T) {
		testinggo.AssertError(t, aliasgo.ErrAliasInvalid{Alias: "foo()bar"}.Error(), aliasgo.ValidateAlias("foo()bar"))
	})
}

// TODO TestCreateAliasRecord
// TODO TestRegisterAlias
