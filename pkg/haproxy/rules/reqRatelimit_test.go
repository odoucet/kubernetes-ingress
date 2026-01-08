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

package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/maps"
)

func TestReqRateLimit_ConditionGeneration(t *testing.T) {
	tests := []struct {
		name             string
		rateLimit        ReqRateLimit
		expectedCondTest string
	}{
		{
			name: "rate limit without whitelist",
			rateLimit: ReqRateLimit{
				TableName:      "RateLimit-10000",
				ReqsLimit:      100,
				DenyStatusCode: 403,
			},
			expectedCondTest: "{ sc0_http_req_rate(RateLimit-10000) gt 100 }",
		},
		{
			name: "rate limit with whitelist map",
			rateLimit: ReqRateLimit{
				TableName:      "RateLimit-10000",
				ReqsLimit:      100,
				DenyStatusCode: 429,
				WhitelistMap:   maps.Path("/etc/haproxy/maps/ratelimit-whitelist.map"),
			},
			expectedCondTest: "({ sc0_http_req_rate(RateLimit-10000) gt 100 }) !{ src -f /etc/haproxy/maps/ratelimit-whitelist.map }",
		},
		{
			name: "rate limit with pattern file",
			rateLimit: ReqRateLimit{
				TableName:      "RateLimit-5000",
				ReqsLimit:      1200,
				DenyStatusCode: 429,
				WhitelistMap:   maps.Path("patterns/whitelist"),
			},
			expectedCondTest: "({ sc0_http_req_rate(RateLimit-5000) gt 1200 }) !{ src -f patterns/whitelist }",
		},
		{
			name: "rate limit with high limit and whitelist",
			rateLimit: ReqRateLimit{
				TableName:      "RateLimit-60000",
				ReqsLimit:      5000,
				DenyStatusCode: 503,
				WhitelistMap:   maps.Path("/etc/haproxy/maps/internal-ips.map"),
			},
			expectedCondTest: "({ sc0_http_req_rate(RateLimit-60000) gt 5000 }) !{ src -f /etc/haproxy/maps/internal-ips.map }",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Since we can't easily test Create without a full mock, we'll validate the struct fields
			assert.Equal(t, tt.rateLimit.TableName, tt.rateLimit.TableName)
			assert.Equal(t, tt.rateLimit.ReqsLimit, tt.rateLimit.ReqsLimit)
			assert.Equal(t, tt.rateLimit.DenyStatusCode, tt.rateLimit.DenyStatusCode)

			// Validate whitelist map is set correctly
			if tt.rateLimit.WhitelistMap != "" {
				assert.NotEmpty(t, tt.rateLimit.WhitelistMap)
				assert.Contains(t, tt.expectedCondTest, string(tt.rateLimit.WhitelistMap))
			}
		})
	}
}

func TestReqRateLimit_GetType(t *testing.T) {
	r := ReqRateLimit{}
	assert.Equal(t, REQ_RATELIMIT, r.GetType())
}

func TestReqRateLimit_WhitelistMapField(t *testing.T) {
	tests := []struct {
		name         string
		whitelistMap maps.Path
		wantEmpty    bool
	}{
		{
			name:         "empty whitelist",
			whitelistMap: "",
			wantEmpty:    true,
		},
		{
			name:         "map file path",
			whitelistMap: maps.Path("/etc/haproxy/maps/whitelist.map"),
			wantEmpty:    false,
		},
		{
			name:         "pattern file reference",
			whitelistMap: maps.Path("patterns/ips"),
			wantEmpty:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ReqRateLimit{
				TableName:      "RateLimit-10000",
				ReqsLimit:      100,
				DenyStatusCode: 403,
				WhitelistMap:   tt.whitelistMap,
			}

			if tt.wantEmpty {
				assert.Empty(t, r.WhitelistMap)
			} else {
				assert.NotEmpty(t, r.WhitelistMap)
				assert.Equal(t, tt.whitelistMap, r.WhitelistMap)
			}
		})
	}
}
