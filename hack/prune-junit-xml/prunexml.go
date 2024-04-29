/*
Copyright 2022 The cert-manager Authors.

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

/*
Copyright 2022 The Kubernetes Authors.
Started from https://github.com/kubernetes/kubernetes/blob/978d9683f5c253cf62225dc0656c0bfeb2a7d339/cmd/prune-junit-xml/prunexml.go
*/

// This tool prevents the junit xml files from becoming too big.
// Because big files cause longer loading times and might break
// some tools. It also improves the web ui experience by reducing
// visual noise.
// More info: https://github.com/kubernetes/kubernetes/pull/109112
//
// The following processing steps are included:
//	- compacting all fuzz tests (often 1000+) into a single entry
//	- removing empty testsuites
//	- clipping the output from failures or skips

package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
)

// JUnitTestSuites is a collection of JUnit test suites.
type JUnitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []JUnitTestSuite `xml:"testsuite,omitempty"`
}

// JUnitTestSuite is a single JUnit test suite which may contain many
// testcases.
type JUnitTestSuite struct {
	XMLName    xml.Name        `xml:"testsuite"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Time       string          `xml:"time,attr"`
	Name       string          `xml:"name,attr"`
	Properties []JUnitProperty `xml:"properties>property,omitempty"`
	TestCases  []JUnitTestCase `xml:"testcase,omitempty"`
	Timestamp  string          `xml:"timestamp,attr"`
}

// JUnitTestCase is a single test case with its result.
type JUnitTestCase struct {
	XMLName     xml.Name          `xml:"testcase"`
	Classname   string            `xml:"classname,attr"`
	Name        string            `xml:"name,attr"`
	Time        string            `xml:"time,attr"`
	SkipMessage *JUnitSkipMessage `xml:"skipped,omitempty"`
	Failure     *JUnitFailure     `xml:"failure,omitempty"`
}

// JUnitSkipMessage contains the reason why a testcase was skipped.
type JUnitSkipMessage struct {
	Message string `xml:"message,attr"`
}

// JUnitProperty represents a key/value pair used to define properties.
type JUnitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// JUnitFailure contains data related to a failed test.
type JUnitFailure struct {
	Message  string `xml:"message,attr"`
	Type     string `xml:"type,attr"`
	Contents string `xml:",chardata"`
}

var fuzzNameRegex = regexp.MustCompile(`^(.*)\/fuzz_\d+$`)

func main() {
	logger := log.New(os.Stderr, "", 0)

	maxTextSize := flag.Int("max-text-size", 1, "maximum size of attribute or text (in MB)")
	flag.Parse()

	if flag.NArg() > 0 {
		for _, path := range flag.Args() {
			logger.Printf("processing junit xml file : %s\n", path)
			xmlReader, err := os.Open(path)
			if err != nil {
				panic(err)
			}
			defer xmlReader.Close()
			suites, err := fetchXML(xmlReader) // convert MB into bytes (roughly!)
			if err != nil {
				panic(err)
			}

			pruneXML(logger, suites, *maxTextSize*1e6) // convert MB into bytes (roughly!)

			xmlWriter, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
			if err != nil {
				panic(err)
			}
			defer xmlWriter.Close()
			err = streamXML(xmlWriter, suites)
			if err != nil {
				panic(err)
			}
			logger.Println("done.")
		}
	}
}

func pruneXML(logger *log.Logger, suites *JUnitTestSuites, maxBytes int) {
	// filter empty testSuites
	filteredSuites := []JUnitTestSuite{}
	for _, suite := range suites.Suites {
		if suite.Tests+suite.Failures+len(suite.TestCases) > 0 {
			filteredSuites = append(filteredSuites, suite)
		}
	}
	suites.Suites = filteredSuites

	// compact fuzz tests
	compactedSuites := []JUnitTestSuite{}
	for _, suite := range suites.Suites {
		filteredTestCases := []*JUnitTestCase{}
		fuzzTestCases := map[string]*JUnitTestCase{}
		for _, testcase := range suite.TestCases {
			testcase := testcase
			matches := fuzzNameRegex.FindStringSubmatch(testcase.Name)
			if len(matches) > 1 {
				if ftc, ok := fuzzTestCases[matches[1]]; ok {
					if testcase.Failure != nil {
						ftc.Failure = testcase.Failure // we only display one failure
						ftc.SkipMessage = nil
					}
					if testcase.SkipMessage != nil && ftc.Failure == nil {
						ftc.SkipMessage = testcase.SkipMessage // only display SkipMessage if no other fuzz has failed
					}
					ftc.Time = incrementTime(ftc.Time, testcase.Time)
				} else {
					testcase.Name = matches[1] + "/fuzz_xxxx"
					fuzzTestCases[matches[1]] = &testcase
					filteredTestCases = append(filteredTestCases, &testcase)
				}
			} else {
				filteredTestCases = append(filteredTestCases, &testcase)
			}
		}

		suite.TestCases = []JUnitTestCase{}
		suite.Tests = 0
		suite.Failures = 0
		for _, testcase := range filteredTestCases {
			suite.TestCases = append(suite.TestCases, *testcase)
			suite.Tests += 1
			if testcase.Failure != nil {
				suite.Failures += 1
			}

		}
		compactedSuites = append(compactedSuites, suite)
	}
	suites.Suites = compactedSuites

	// clip output messages
	for _, suite := range suites.Suites {
		for _, testcase := range suite.TestCases {
			if testcase.SkipMessage != nil {
				if len(testcase.SkipMessage.Message) > maxBytes {
					logger.Printf("clipping skip message in test case : %s\n", testcase.Name)
					testcase.SkipMessage.Message = "[... clipped...]" +
						testcase.SkipMessage.Message[len(testcase.SkipMessage.Message)-maxBytes:]
				}
			}
			if testcase.Failure != nil {
				if len(testcase.Failure.Contents) > maxBytes {
					logger.Printf("clipping failure message in test case : %s\n", testcase.Name)
					testcase.Failure.Contents = "[... clipped...]" +
						testcase.Failure.Contents[len(testcase.Failure.Contents)-maxBytes:]
				}
			}
		}
	}
}

func incrementTime(total string, delta string) string {
	totalTime, err := strconv.ParseFloat(total, 32)
	if err != nil {
		return total
	}
	deltaTime, err := strconv.ParseFloat(delta, 32)
	if err != nil {
		return total
	}
	return fmt.Sprintf("%.6f", totalTime+deltaTime)
}

func fetchXML(xmlReader io.Reader) (*JUnitTestSuites, error) {
	decoder := xml.NewDecoder(xmlReader)
	var suites JUnitTestSuites
	err := decoder.Decode(&suites)
	if err != nil {
		return nil, err
	}
	return &suites, nil
}

func streamXML(writer io.Writer, in *JUnitTestSuites) error {
	_, err := writer.Write([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"))
	if err != nil {
		return err
	}
	encoder := xml.NewEncoder(writer)
	encoder.Indent("", "\t")
	err = encoder.Encode(in)
	if err != nil {
		return err
	}
	return encoder.Flush()
}
