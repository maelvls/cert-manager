//go:build e2e_test

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

package e2e

import (
	"flag"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	_ "github.com/cert-manager/cert-manager/test/e2e/suite"
)

var featureGates string

func TestE2E(t *testing.T) {
	logs.InitLogs(flag.CommandLine)
	defer logs.FlushLogs()
	framework.DefaultConfig.AddFlags(flag.CommandLine)

	flag.Parse()

	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()

	reporterConfig.Verbose = true
	suiteConfig.EmitSpecProgress = true
	suiteConfig.RandomizeAllSpecs = true
	wait.ForeverTestTimeout = time.Second * 60

	// Disable skipped tests unless they are explicitly requested.
	// Copied from https://github.com/kubernetes/kubernetes/blob/960e5e78255dd148d4dae49f62e729ea940f4f07/test/e2e/e2e.go#L103-L106
	// See https://github.com/kubernetes/community/blob/master/contributors/devel/sig-testing/flaky-tests.md#quarantining-flakes
	if len(suiteConfig.FocusStrings) == 0 && len(suiteConfig.SkipStrings) == 0 {
		suiteConfig.SkipStrings = []string{`\[Flaky\]`}
	}

	if err := framework.DefaultConfig.Validate(); err != nil {
		t.Fatalf("Invalid test config: %v", err)
	}

	gomega.NewWithT(t)
	gomega.RegisterFailHandler(ginkgo.Fail)

	// TODO: properly make use of default SkipString
	// Disable skipped tests unless they are explicitly requested.
	// if suiteConfig.FocusString == "" && suiteConfig.SkipString == "" {
	// 	suiteConfig.SkipString = `\[Flaky\]|\[Feature:.+\]`
	// }

	ginkgo.RunSpecs(t, "cert-manager e2e suite")
}
