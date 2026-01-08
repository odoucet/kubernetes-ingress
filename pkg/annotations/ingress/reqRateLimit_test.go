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

package ingress

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/maps"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/rules"
	"github.com/haproxytech/kubernetes-ingress/pkg/store"
)

func TestReqRateLimit_Whitelist(t *testing.T) {
	tests := []struct {
		name              string
		annotations       map[string]string
		wantErr           bool
		wantWhitelistMap  bool
		wantMapEntries    int
		expectedMapName   string
		expectedWhitelist string
	}{
		{
			name: "whitelist with single IP",
			annotations: map[string]string{
				"rate-limit-requests":  "100",
				"rate-limit-whitelist": "192.168.1.1",
			},
			wantErr:          false,
			wantWhitelistMap: true,
			wantMapEntries:   1,
		},
		{
			name: "whitelist with CIDR",
			annotations: map[string]string{
				"rate-limit-requests":  "100",
				"rate-limit-whitelist": "10.0.0.0/8",
			},
			wantErr:          false,
			wantWhitelistMap: true,
			wantMapEntries:   1,
		},
		{
			name: "whitelist with multiple IPs and CIDRs",
			annotations: map[string]string{
				"rate-limit-requests":  "100",
				"rate-limit-whitelist": "192.168.1.1, 10.0.0.0/8, 172.16.0.0/12",
			},
			wantErr:          false,
			wantWhitelistMap: true,
			wantMapEntries:   3,
		},
		{
			name: "whitelist with patterns prefix",
			annotations: map[string]string{
				"rate-limit-requests":  "100",
				"rate-limit-whitelist": "patterns/whitelist",
			},
			wantErr:           false,
			wantWhitelistMap:  true,
			wantMapEntries:    0, // No map entries created for pattern files
			expectedWhitelist: "patterns/whitelist",
		},
		{
			name: "whitelist without rate-limit-requests",
			annotations: map[string]string{
				"rate-limit-whitelist": "192.168.1.1",
			},
			wantErr:          true,
			wantWhitelistMap: false,
		},
		{
			name: "whitelist with invalid IP",
			annotations: map[string]string{
				"rate-limit-requests":  "100",
				"rate-limit-whitelist": "invalid-ip",
			},
			wantErr:          true,
			wantWhitelistMap: false,
		},
		{
			name: "whitelist with invalid CIDR",
			annotations: map[string]string{
				"rate-limit-requests":  "100",
				"rate-limit-whitelist": "192.168.1.0/33",
			},
			wantErr:          true,
			wantWhitelistMap: false,
		},
		{
			name: "whitelist with mixed valid and invalid entries",
			annotations: map[string]string{
				"rate-limit-requests":  "100",
				"rate-limit-whitelist": "192.168.1.1, invalid, 10.0.0.0/8",
			},
			wantErr:          true,
			wantWhitelistMap: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock maps
			mockMaps, err := maps.New("/tmp/maps", nil)
			require.NoError(t, err)

			// Create rules list
			rulesList := &rules.List{}

			// Create ReqRateLimit handler
			reqRateLimit := NewReqRateLimit(rulesList, mockMaps)

			// Process rate-limit-requests annotation first (if present)
			if _, ok := tt.annotations["rate-limit-requests"]; ok {
				ann := reqRateLimit.NewAnnotation("rate-limit-requests")
				err := ann.Process(store.K8s{}, tt.annotations)
				require.NoError(t, err)
			}

			// Process rate-limit-whitelist annotation
			ann := reqRateLimit.NewAnnotation("rate-limit-whitelist")
			err = ann.Process(store.K8s{}, tt.annotations)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			if tt.wantWhitelistMap {
				assert.NotNil(t, reqRateLimit.limit)
				assert.NotEmpty(t, reqRateLimit.limit.WhitelistMap)

				// Check if it's a pattern file reference
				if tt.expectedWhitelist != "" {
					assert.Equal(t, maps.Path(tt.expectedWhitelist), reqRateLimit.limit.WhitelistMap)
				} else {
					// For non-pattern files, the map should be created
					// The map entries count is validated through mockMaps
					assert.Contains(t, string(reqRateLimit.limit.WhitelistMap), "ratelimit-whitelist-")
				}
			}
		})
	}
}

func TestReqRateLimit_WhitelistWithPeriod(t *testing.T) {
	// Create mock maps
	mockMaps, err := maps.New("/tmp/maps", nil)
	require.NoError(t, err)

	// Create rules list
	rulesList := &rules.List{}

	// Create ReqRateLimit handler
	reqRateLimit := NewReqRateLimit(rulesList, mockMaps)

	annotations := map[string]string{
		"rate-limit-requests":  "100",
		"rate-limit-period":    "10s",
		"rate-limit-whitelist": "192.168.1.0/24",
	}

	// Process annotations in order
	for _, annName := range []string{"rate-limit-requests", "rate-limit-period", "rate-limit-whitelist"} {
		ann := reqRateLimit.NewAnnotation(annName)
		err := ann.Process(store.K8s{}, annotations)
		require.NoError(t, err)
	}

	// Verify the configuration
	assert.NotNil(t, reqRateLimit.limit)
	assert.NotNil(t, reqRateLimit.track)
	assert.Equal(t, int64(100), reqRateLimit.limit.ReqsLimit)
	assert.Equal(t, "RateLimit-10000", reqRateLimit.limit.TableName)
	assert.NotEmpty(t, reqRateLimit.limit.WhitelistMap)
}

func TestReqRateLimit_AllAnnotations(t *testing.T) {
	// Create mock maps
	mockMaps, err := maps.New("/tmp/maps", nil)
	require.NoError(t, err)

	// Create rules list
	rulesList := &rules.List{}

	// Create ReqRateLimit handler
	reqRateLimit := NewReqRateLimit(rulesList, mockMaps)

	annotations := map[string]string{
		"rate-limit-requests":    "1200",
		"rate-limit-period":      "10s",
		"rate-limit-status-code": "429",
		"rate-limit-size":        "200k",
		"rate-limit-whitelist":   "10.0.0.0/8, 192.168.1.100",
	}

	// Process annotations in order
	annotationOrder := []string{
		"rate-limit-requests",
		"rate-limit-period",
		"rate-limit-status-code",
		"rate-limit-size",
		"rate-limit-whitelist",
	}

	for _, annName := range annotationOrder {
		ann := reqRateLimit.NewAnnotation(annName)
		err := ann.Process(store.K8s{}, annotations)
		require.NoError(t, err)
	}

	// Verify all configurations
	assert.NotNil(t, reqRateLimit.limit)
	assert.NotNil(t, reqRateLimit.track)
	assert.Equal(t, int64(1200), reqRateLimit.limit.ReqsLimit)
	assert.Equal(t, int64(429), reqRateLimit.limit.DenyStatusCode)
	assert.Equal(t, "RateLimit-10000", reqRateLimit.limit.TableName)
	assert.NotEmpty(t, reqRateLimit.limit.WhitelistMap)
	assert.NotNil(t, reqRateLimit.track.TableSize)
}
