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
	"encoding/json"
	"fmt"
	"hash/fnv"
	"regexp"
)

const MaxPodNameLength = 63

// ComputeUniqueDeterministicNameFromObject hashes the given object and prefixes it with prefix.
// The algorithm in use is Fowler–Noll–Vo hash function and is not
// cryptographically secure. Using a cryptographically secure hash is
// not necessary.
func ComputeUniqueDeterministicNameFromObject(prefix string, obj interface{}) (string, error) {
	objectBytes, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}

	return ComputeUniqueDeterministicNameFromData(prefix, MaxPodNameLength, objectBytes)
}

// ComputeUniqueDeterministicNameFromData returns a short unique name for the given object.
func ComputeUniqueDeterministicNameFromData(fullName string, maxNameLength int, data ...[]byte) (string, error) {
	const hashLength = 8
	if maxNameLength <= hashLength {
		return "", fmt.Errorf("maxNameLength must be at least %d", hashLength+1)
	}

	if len(fullName) <= maxNameLength && len(data) == 0 {
		return fullName, nil
	}

	var maxGeneratedNameLength = maxNameLength - hashLength - 1 // -1 for the hyphen

	hashF := fnv.New32()

	_, err := hashF.Write([]byte(fullName))
	if err != nil {
		return "", err
	}

	for _, d := range data {
		_, err := hashF.Write(d)
		if err != nil {
			return "", err
		}
	}

	prefix := DNSSafeShortenToNCharacters(fullName, maxGeneratedNameLength)

	if len(prefix) == 0 {
		return fmt.Sprintf("%08x", hashF.Sum32()), nil
	}

	return fmt.Sprintf("%s-%08x", prefix, hashF.Sum32()), nil
}

// DNSSafeShortenToNCharacters shortens the input string to 52 chars and ensures the last char is an alpha-numeric character.
func DNSSafeShortenToNCharacters(in string, maxLength int) string {
	var alphaNumeric = regexp.MustCompile(`[a-zA-Z\d]`)

	if len(in) < maxLength {
		return in
	}

	validCharIndexes := alphaNumeric.FindAllStringIndex(in[:maxLength], -1)
	if len(validCharIndexes) == 0 {
		return ""
	}

	return in[:validCharIndexes[len(validCharIndexes)-1][1]]
}

// ComputeName hashes the given object and prefixes it with prefix.
// The algorithm in use is Fowler–Noll–Vo hash function and is not
// cryptographically secure. Using a cryptographically secure hash is
// not necessary.
// Deprecated: Use ComputeUniqueDeterministicNameFromObject instead.
func ComputeName(prefix string, obj interface{}) (string, error) {
	return ComputeUniqueDeterministicNameFromObject(prefix, obj)
}

// DNSSafeShortenTo52Characters shortens the input string to 52 chars and ensures the last char is an alpha-numeric character.
// Deprecated: Use DNSSafeShortenToNCharacters instead.
func DNSSafeShortenTo52Characters(in string) string {
	return DNSSafeShortenToNCharacters(in, 52)
}
