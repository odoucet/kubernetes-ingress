// Copyright 2019 HAProxy Technologies LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package accesscontrol

import (
	"os"
	"path/filepath"
	"strings"
)

// TestSrcIPHeaderWithAllowList verifies the generated HAProxy configuration when both
// the "src-ip-header" and "allow-list" annotations are used together.
//
// When behind a proxy like Cloudflare, the real client IP is carried in an HTTP header
// (e.g. "CF-Connecting-IP"). The "src-ip-header" annotation instructs HAProxy to update
// the connection source address from that header via "http-request set-src". The
// "allow-list" annotation then adds a deny rule that checks the source address against
// an IP allowlist via "http-request deny ... if !{ src -f <map> }".
//
// For the combination to work correctly, the set-src rule MUST appear BEFORE the deny
// rule in the generated HAProxy frontend configuration, so that the deny check uses
// the header-derived IP rather than the original TCP source address.
func (suite *AccessControlSuite) TestSrcIPHeaderWithAllowList() {
	suite.UseAccessControlFixture(map[string]string{
		"src-ip-header": "X-Client-IP",
		"allow-list":    "192.168.2.0/24",
	})

	contents, err := os.ReadFile(filepath.Join(suite.test.TempDir, "haproxy.cfg"))
	if err != nil {
		suite.T().Fatal(err.Error())
	}
	cfg := string(contents)

	suite.Run("set-src rule is present", func() {
		suite.Contains(cfg, "http-request set-src hdr(X-Client-IP)", "expected http-request set-src rule for src-ip-header annotation")
	})

	suite.Run("deny rule is present", func() {
		suite.Contains(cfg, "http-request deny deny_status 403", "expected http-request deny rule for allow-list annotation")
	})

	suite.Run("set-src rule appears before deny rule", func() {
		setSrcIdx := strings.Index(cfg, "http-request set-src hdr(X-Client-IP)")
		denyIdx := strings.Index(cfg, "http-request deny deny_status 403")

		suite.Require().Greater(setSrcIdx, -1, "http-request set-src rule not found")
		suite.Require().Greater(denyIdx, -1, "http-request deny rule not found")

		suite.Less(setSrcIdx, denyIdx,
			"http-request set-src must appear before http-request deny so that the "+
				"allow-list check uses the IP from the src-ip-header, not the TCP source address")
	})
}

// TestSrcIPHeaderWithDenyList verifies the generated HAProxy configuration when both
// the "src-ip-header" and "deny-list" annotations are used together.
//
// Similarly to the allow-list case, set-src must run before the deny check so that
// the deny-list check uses the header-derived IP.
func (suite *AccessControlSuite) TestSrcIPHeaderWithDenyList() {
	suite.UseAccessControlFixture(map[string]string{
		"src-ip-header": "X-Forwarded-For",
		"deny-list":     "10.0.0.0/8",
	})

	contents, err := os.ReadFile(filepath.Join(suite.test.TempDir, "haproxy.cfg"))
	if err != nil {
		suite.T().Fatal(err.Error())
	}
	cfg := string(contents)

	suite.Run("set-src rule is present", func() {
		suite.Contains(cfg, "http-request set-src hdr(X-Forwarded-For)", "expected http-request set-src rule for src-ip-header annotation")
	})

	suite.Run("deny rule is present", func() {
		suite.Contains(cfg, "http-request deny deny_status 403", "expected http-request deny rule for deny-list annotation")
	})

	suite.Run("set-src rule appears before deny rule", func() {
		checked := 0
		for _, section := range strings.Split(cfg, "frontend ") {
			if !strings.HasPrefix(section, "http ") && !strings.HasPrefix(section, "https ") {
				continue
			}
			if !strings.Contains(section, "http-request deny deny_status 403") {
				continue
			}
			checked++
			setSrcIdx := strings.Index(section, "http-request set-src hdr(X-Forwarded-For)")
			denyIdx := strings.Index(section, "http-request deny deny_status 403")
			suite.Require().Greater(setSrcIdx, -1, "http-request set-src rule not found in frontend")
			suite.Require().Greater(denyIdx, -1, "http-request deny rule not found in frontend")
			suite.Less(setSrcIdx, denyIdx,
				"http-request set-src must appear before http-request deny so that the "+
					"deny-list check uses the IP from the src-ip-header, not the TCP source address")
		}
		suite.Require().Greater(checked, 0, "no relevant frontend section with deny rule found")
	})
}
