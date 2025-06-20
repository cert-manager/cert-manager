/*
Copyright 2020 The cert-manager Authors.

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

package util

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"regexp"
)

// ComputeName hashes the given object and prefixes it with prefix.
// The algorithm in use is Fowler–Noll–Vo hash function and is not
// cryptographically secure. Using a cryptographically secure hash is
// not necessary.
func ComputeName(prefix string, obj interface{}) (string, error) {
	objectBytes, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}

	hashF := fnv.New32()
	_, err = hashF.Write(objectBytes)
	if err != nil {
		return "", err
	}

	// we're shortening to stay under 64 as we use this in services
	// and pods down the road for ACME resources.
	prefix = DNSSafeShortenTo52Characters(prefix)

	// the prefix is <= 52 characters, the decimal representation of
	// the hash is <= 10 characters, and the hyphen is 1 character.
	// 52 + 10 + 1 = 63, so we're good.
	return fmt.Sprintf("%s-%d", prefix, hashF.Sum32()), nil
}

// ComputeSecureUniqueDeterministicNameFromData computes a deterministic name from the given data.
// The algorithm in use is SHA256 and is cryptographically secure.
// The output is a string that is safe to use as a DNS label.
// The output is guaranteed to be unique for the given input.
// The output will be at least 64 characters long.
func ComputeSecureUniqueDeterministicNameFromData(fullName string, maxNameLength int) (string, error) {
	const hashLength = 64
	if maxNameLength < hashLength {
		return "", fmt.Errorf("maxNameLength must be at least %d", hashLength)
	}

	if len(fullName) <= maxNameLength {
		return fullName, nil
	}

	hash := sha256.New()

	_, err := hash.Write([]byte(fullName))
	if err != nil {
		return "", err
	}

	// Although fullName is already a DNS subdomain, we can't just cut it
	// at N characters and expect another DNS subdomain. That's because
	// we might cut it right after a ".", which would give an invalid DNS
	// subdomain (e.g., test.-<hash>). So we make sure the last character
	// is an alpha-numeric character.
	prefix := DNSSafeShortenToNCharacters(fullName, maxNameLength-hashLength-1)
	hashResult := hash.Sum(nil)

	if len(prefix) == 0 {
		return fmt.Sprintf("%08x", hashResult), nil
	}

	return fmt.Sprintf("%s-%08x", prefix, hashResult), nil
}

// DNSSafeShortenToNCharacters shortens the input string to N chars and ensures the last char is an alpha-numeric character.
func DNSSafeShortenToNCharacters(in string, maxLength int) string {
	var alphaNumeric = regexp.MustCompile(`[a-zA-Z\d]`)

	if len(in) < maxLength {
		return in
	}

	if maxLength <= 0 {
		return ""
	}

	validCharIndexes := alphaNumeric.FindAllStringIndex(in[:maxLength], -1)
	if len(validCharIndexes) == 0 {
		return ""
	}

	return in[:validCharIndexes[len(validCharIndexes)-1][1]]
}

// DNSSafeShortenTo52Characters shortens the input string to 52 chars and ensures the last char is an alpha-numeric character.
func DNSSafeShortenTo52Characters(in string) string {
	return DNSSafeShortenToNCharacters(in, 52)
}
