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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// inplaceReadValuesYAML reads the provided chart tar file and returns the values
func readValuesYAML(inputPath string) (map[string]any, error) {
	var result map[string]any
	return result, modifyValuesYAML(inputPath, "", func(m map[string]any) (map[string]any, error) {
		result = m
		return m, nil
	})
}

type modFunction func(map[string]any) (map[string]any, error)

func modifyValuesYAML(inFilePath string, outFilePath string, modFn modFunction) error {
	inReader, err := os.Open(inFilePath)
	if err != nil {
		return err
	}
	defer inReader.Close()
	outWriter := io.Discard
	if outFilePath != "" {
		outFile, err := os.Create(outFilePath)
		if err != nil {
			return err
		}
		defer outFile.Close()
		outWriter = outFile
	}
	if strings.HasSuffix(inFilePath, ".tgz") {
		if err := modifyTarStreamValuesYAML(inReader, outWriter, modFn); err != nil {
			return err
		}
	} else {
		if err := modifyStreamValuesYAML(inReader, outWriter, modFn); err != nil {
			return err
		}
	}
	return nil
}

func modifyTarStreamValuesYAML(in io.Reader, out io.Writer, modFn modFunction) error {
	inFileDecompressed, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer inFileDecompressed.Close()
	tr := tar.NewReader(inFileDecompressed)
	outFileCompressed, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return err
	}
	outFileCompressed.Extra = []byte("+aHR0cHM6Ly95b3V0dS5iZS96OVV6MWljandyTQo=")
	outFileCompressed.Comment = "Helm"
	defer outFileCompressed.Close()
	tw := tar.NewWriter(outFileCompressed)
	defer tw.Close()
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return err
		}
		const maxValuesYAMLSize = 2 * 1024 * 1024 // 2MB
		limitedReader := &io.LimitedReader{
			R: tr,
			N: maxValuesYAMLSize,
		}
		if strings.HasSuffix(hdr.Name, "/values.yaml") {
			var modifiedContent bytes.Buffer
			if err := modifyStreamValuesYAML(limitedReader, &modifiedContent, modFn); err != nil {
				return err
			}
			// Update header size
			hdr.Size = int64(modifiedContent.Len())
			// Write updated header and content
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if _, err := tw.Write(modifiedContent.Bytes()); err != nil {
				return err
			}
		} else {
			// Stream other files unchanged
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if _, err := io.Copy(tw, limitedReader); err != nil {
				return err
			}
		}
		if limitedReader.N <= 0 {
			return fmt.Errorf("values.yaml is larger than %v bytes", maxValuesYAMLSize)
		}
	}
	return nil
}

func modifyStreamValuesYAML(in io.Reader, out io.Writer, modFn modFunction) error {
	// Parse YAML
	var data map[string]any
	if err := yaml.NewDecoder(in).Decode(&data); err != nil {
		return err
	}
	// Modify YAML
	data, err := modFn(data)
	if err != nil {
		return err
	}
	// Marshal back to YAML
	return yaml.NewEncoder(out).Encode(data)
}
