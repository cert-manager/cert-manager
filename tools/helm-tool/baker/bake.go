/*
Copyright 2026 The cert-manager Authors.
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
package baker

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type BakeReference struct {
	Repository string
	Tag        string
	Digest     string
}

func ParseBakeReference(value string) (bakeInput BakeReference) {
	// extract digest from value
	if digestRef, err := name.NewDigest(value); err == nil {
		bakeInput.Repository = digestRef.Context().String()
		bakeInput.Digest = digestRef.DigestStr()
	}
	// extract tag from value
	if tagRef, err := name.NewTag(value); err == nil {
		bakeInput.Repository = tagRef.Context().String()
		bakeInput.Tag = tagRef.TagStr()
	}
	return bakeInput
}

func (br BakeReference) Reference() name.Reference {
	repo, _ := name.NewRepository(br.Repository)
	if br.Digest != "" {
		return repo.Digest(br.Digest)
	}
	return repo.Tag(br.Tag)
}

func (br BakeReference) String() string {
	var builder strings.Builder
	_, _ = builder.WriteString(br.Repository)
	if br.Tag != "" {
		_, _ = builder.WriteString(":")
		_, _ = builder.WriteString(br.Tag)
	}
	if br.Digest != "" {
		_, _ = builder.WriteString("@")
		_, _ = builder.WriteString(br.Digest)
	}
	return builder.String()
}

type BakeInput = BakeReference

func (bi BakeInput) Find(ctx context.Context) (BakeOutput, error) {
	desc, err := remote.Head(bi.Reference(), remote.WithContext(ctx))
	if err != nil {
		return BakeReference{}, fmt.Errorf("failed to pull %s", bi)
	}
	return BakeReference{
		Repository: bi.Repository,
		Digest:     desc.Digest.String(),
		Tag:        bi.Tag,
	}, nil
}

type BakeOutput = BakeReference

func Extract(ctx context.Context, inputPath string) (map[string]BakeInput, error) {
	results := map[string]BakeInput{}
	values, err := readValuesYAML(inputPath)
	if err != nil {
		return nil, err
	}
	if _, err := allNestedStringValues(values, nil, func(path []string, value string) (string, error) {
		if path[len(path)-1] != "_defaultReference" {
			return value, nil
		}
		bakeInput := ParseBakeReference(value)
		if bakeInput == (BakeInput{}) {
			return "", fmt.Errorf("invalid _defaultReference value: %q", value)
		}
		results[strings.Join(path, ".")] = bakeInput
		return value, nil
	}); err != nil {
		return nil, err
	}
	return results, nil
}

type BakeAction struct {
	In  BakeInput  `json:"in"`
	Out BakeOutput `json:"out"`
}

func Bake(ctx context.Context, inputPath string, outputPath string, valuesPaths []string) (map[string]BakeAction, error) {
	results := map[string]BakeAction{}
	return results, modifyValuesYAML(inputPath, outputPath, func(values map[string]any) (map[string]any, error) {
		replacedValuePaths := map[string]struct{}{}
		newValues, err := allNestedStringValues(values, nil, func(path []string, value string) (string, error) {
			if path[len(path)-1] != "_defaultReference" {
				return value, nil
			}
			bakeInput := ParseBakeReference(value)
			if bakeInput == (BakeInput{}) {
				return "", fmt.Errorf("invalid _defaultReference value: %q", value)
			}
			bakeOutput, err := bakeInput.Find(ctx)
			if err != nil {
				return "", err
			}
			pathString := strings.Join(path, ".")
			replacedValuePaths[pathString] = struct{}{}
			results[pathString] = BakeAction{
				In:  bakeInput,
				Out: bakeOutput,
			}
			return bakeOutput.String(), nil
		})
		if err != nil {
			return nil, err
		}
		if len(replacedValuePaths) > len(valuesPaths) {
			return nil, fmt.Errorf("too many value paths were replaced: %v", slices.Collect(maps.Keys(replacedValuePaths)))
		}
		for _, valuesPath := range valuesPaths {
			if _, ok := replacedValuePaths[valuesPath]; !ok {
				return nil, fmt.Errorf("path was not replaced: %s", valuesPath)
			}
		}
		return newValues.(map[string]any), nil
	})
}

func allNestedStringValues(object any, path []string, fn func(path []string, value string) (string, error)) (any, error) {
	switch t := object.(type) {
	case map[string]any:
		for key, value := range t {
			keyPath := append(path, key)
			if stringValue, ok := value.(string); ok {
				newValue, err := fn(slices.Clone(keyPath), stringValue)
				if err != nil {
					return nil, err
				}
				t[key] = newValue
			} else {
				newValue, err := allNestedStringValues(value, keyPath, fn)
				if err != nil {
					return nil, err
				}
				t[key] = newValue
			}
		}
	case map[string]string:
		for key, stringValue := range t {
			keyPath := append(path, key)
			newValue, err := fn(slices.Clone(keyPath), stringValue)
			if err != nil {
				return nil, err
			}
			t[key] = newValue
		}
	case []any:
		for i, value := range t {
			path = append(path, fmt.Sprintf("%d", i))
			newValue, err := allNestedStringValues(value, path, fn)
			if err != nil {
				return nil, err
			}
			t[i] = newValue
		}
	default:
		// ignore object
	}
	return object, nil
}
