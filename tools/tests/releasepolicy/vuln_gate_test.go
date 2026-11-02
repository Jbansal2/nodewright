// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package releasepolicy

import (
	"slices"
	"strings"
	"testing"
)

const vulnGateAction = "./.github/actions/vuln-gate"

// TestImageReleasesWaitForTheVulnerabilityGate pins the release gate in the two
// image workflows: a tag build scans each platform image, and the job that
// creates the version index, signs it and moves latest runs only once that scan
// passed. The tempting refactor is dropping the gate from create-manifest's
// needs, or loosening its if: to always(), either of which lets a release with a
// fixable critical or high finding publish exactly as before.
func TestImageReleasesWaitForTheVulnerabilityGate(t *testing.T) {
	t.Parallel()
	for _, workflow := range []string{operatorCIPath, agentCIPath} {
		t.Run(workflow, func(t *testing.T) {
			t.Parallel()
			w := loadWorkflow(t, workflow)

			var gate *NamedJob
			for i := range w.Jobs {
				if w.Jobs[i].ID == "vuln-gate" {
					gate = &w.Jobs[i]
				}
			}
			if gate == nil {
				t.Fatalf("%s has no vuln-gate job; release tags would publish unscanned", workflow)
			}
			if got := len(gate.Job.Steps.using(vulnGateAction)); got != 1 {
				t.Errorf("%s vuln-gate calls %s %d times, want 1", workflow, vulnGateAction, got)
			}
			if !strings.Contains(gate.Job.If, "github.ref_type == 'tag'") {
				t.Errorf("%s vuln-gate if: %q must run on every tag, release candidates included", workflow, gate.Job.If)
			}

			publisher := w.publishingJob(t)
			if !slices.Contains(publisher.Job.Needs, "vuln-gate") {
				t.Errorf("%s %s needs %v, which must include vuln-gate: the version index and its signature have to wait for the scan", workflow, publisher.ID, publisher.Job.Needs)
			}
			if !strings.Contains(publisher.Job.If, "needs.vuln-gate.result == 'success'") {
				t.Errorf(`%s %s if: %q must require needs.vuln-gate.result == 'success'.
It also runs when the gate is skipped (every event but a tag), so it cannot
rely on the default success(); without the explicit check a failed gate
would not stop it.`, workflow, publisher.ID, publisher.Job.If)
			}
			if strings.Contains(publisher.Job.If, "always()") {
				t.Errorf("%s %s if: %q must not use always(), which would run it after a failed gate", workflow, publisher.ID, publisher.Job.If)
			}
		})
	}
}

// TestJobsAfterTheVulnerabilityGateRunWhenItIsSkipped pins that every job
// downstream of vuln-gate still runs on the events where the gate is skipped
// (every event but a tag). GitHub's default if: is success(), which skips a job
// when any ancestor was skipped, not only its direct needs, so a job two hops
// below the gate silently stops running on pull requests and main, and the
// workflow's gate job then fails because a job it requires never ran. A job that
// runs only on tags is exempt: the gate always runs there.
func TestJobsAfterTheVulnerabilityGateRunWhenItIsSkipped(t *testing.T) {
	t.Parallel()
	for _, workflow := range []string{operatorCIPath, agentCIPath} {
		t.Run(workflow, func(t *testing.T) {
			t.Parallel()
			w := loadWorkflow(t, workflow)
			needs := map[string][]string{}
			for _, job := range w.Jobs {
				needs[job.ID] = job.Job.Needs
			}
			var downstream func(id string, seen map[string]bool) bool
			downstream = func(id string, seen map[string]bool) bool {
				for _, need := range needs[id] {
					if need == "vuln-gate" {
						return true
					}
					if !seen[need] {
						seen[need] = true
						if downstream(need, seen) {
							return true
						}
					}
				}
				return false
			}
			for _, job := range w.Jobs {
				if !downstream(job.ID, map[string]bool{}) || strings.HasPrefix(job.Job.If, "startsWith(github.ref, 'refs/tags/") {
					continue
				}
				if !strings.Contains(job.Job.If, "!cancelled()") && !strings.Contains(job.Job.If, "always()") {
					t.Errorf("%s %s runs after vuln-gate, which is skipped on every event but a tag, so its if: %q is skipped there too; use !cancelled() with explicit needs.<job>.result checks", workflow, job.ID, job.Job.If)
				}
			}
		})
	}
}

// TestCLIReleaseIsScannedBeforeItIsSigned pins the CLI's gate: both scanned
// platforms come after the push that creates the index and before anything signs
// it or moves latest, so a blocked CLI release is never signed and never becomes
// what scripts/install-cli.sh installs by default.
func TestCLIReleaseIsScannedBeforeItIsSigned(t *testing.T) {
	t.Parallel()
	steps := loadWorkflow(t, cliReleasePath).publishingJob(t).Job.Steps

	index := func(match func(Step) bool) int {
		return slices.IndexFunc(steps, match)
	}
	push := index(func(s Step) bool { return s.Name == "Push the CLI artifact index" })
	sign := index(func(s Step) bool { return strings.HasPrefix(s.Uses, "./.github/actions/cosign-attest-multiplatform") })
	latest := index(func(s Step) bool { return s.Name == "Move latest to the newest stable release" })
	resolve := index(func(s Step) bool { return s.ID == "digest" })
	if push < 0 || sign < 0 || latest < 0 || resolve < 0 {
		t.Fatalf("publish-oci is missing a step this test orders the gate against (push %d, sign %d, latest %d, resolve %d)", push, sign, latest, resolve)
	}

	var platforms []string
	for i, step := range steps {
		if !strings.HasPrefix(step.Uses, vulnGateAction) {
			continue
		}
		platforms = append(platforms, step.With["platform"])
		if i < push || i > sign || i > latest {
			t.Errorf("CLI gate step %q is at %d; it must run after the push (%d) and before signing (%d) and moving latest (%d)", step.Name, i, push, sign, latest)
		}
		// Scanning the tag instead would let another run for the same tag move it
		// between the scan and the signature, so the signed index could be one
		// that never passed.
		if i < resolve || step.With["image"] != "${{ steps.digest.outputs.subject }}" {
			t.Errorf("CLI gate step %q scans %q at %d; it must scan the digest the index is signed by, resolved before it (%d)", step.Name, step.With["image"], i, resolve)
		}
	}
	slices.Sort(platforms)
	if want := []string{"linux/amd64", "windows/amd64"}; !slices.Equal(platforms, want) {
		t.Errorf("CLI gate scans platforms %v, want %v: Linux stands for macOS too, Windows links modules no other platform does", platforms, want)
	}
}

// TestVulnerabilityGateKeepsFindingsOutOfPublicLogs pins how the gate runs
// grype. A release run's log is public, while the scheduled scan keeps findings
// in code scanning, which only maintainers can read. A table or JSON report on
// stdout would publish every finding on the run that fails.
func TestVulnerabilityGateKeepsFindingsOutOfPublicLogs(t *testing.T) {
	t.Parallel()
	action := loadAction(t, ".github/actions/vuln-gate/action.yml")
	var script string
	for _, step := range action.Runs.Steps {
		script += step.Run
	}
	for _, want := range []string{"--quiet", "--file", "--fail-on high", "--only-fixed", "--vex .openvex.json", "--config .grype.yaml"} {
		if !strings.Contains(script, want) {
			t.Errorf("%s runs grype without %s", action.path, want)
		}
	}
}
