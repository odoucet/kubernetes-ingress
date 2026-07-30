// Copyright 2024 HAProxy Technologies LLC
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

package annotations_test

import (
	"reflect"
	"testing"

	"github.com/haproxytech/client-native/v6/models"

	annservice "github.com/haproxytech/kubernetes-ingress/pkg/annotations/service"
	"github.com/haproxytech/kubernetes-ingress/pkg/store"
	"github.com/haproxytech/kubernetes-ingress/pkg/utils"
)

// processCookie is a helper that creates a new Cookie annotation handler for the given
// backend, calls Process with the provided annotation maps, and returns the error.
func processCookie(backend *models.Backend, annotations ...map[string]string) error {
	c := annservice.NewCookie("cookie-persistence", backend)
	return c.Process(store.K8s{}, annotations...)
}

// expectedDynamicCookie returns the expected models.Cookie for a dynamic cookie.
func expectedDynamicCookie(name string) *models.Cookie {
	return &models.Cookie{
		Name:     utils.PtrString(name),
		Type:     "insert",
		Nocache:  true,
		Indirect: true,
		Dynamic:  true,
		Domains:  []*models.Domain{},
	}
}

// expectedNoDynamicCookie returns the expected models.Cookie for a non-dynamic cookie.
func expectedNoDynamicCookie(name string) *models.Cookie {
	return &models.Cookie{
		Name:     utils.PtrString(name),
		Type:     "insert",
		Nocache:  true,
		Indirect: true,
		Dynamic:  false,
		Domains:  []*models.Domain{},
	}
}

// TestCookie_Process tests the Cookie annotation processing for the standard cases.
func TestCookie_Process(t *testing.T) {
	tests := []struct {
		name        string
		annotations []map[string]string
		wantCookie  *models.Cookie
		wantErr     bool
	}{
		{
			name: "dynamic cookie",
			annotations: []map[string]string{
				{"cookie-persistence": "mycookie"},
			},
			wantCookie: expectedDynamicCookie("mycookie"),
		},
		{
			name: "no-dynamic cookie",
			annotations: []map[string]string{
				{"cookie-persistence-no-dynamic": "mycookie"},
			},
			wantCookie: expectedNoDynamicCookie("mycookie"),
		},
		{
			name: "both dynamic and no-dynamic annotations set returns error",
			annotations: []map[string]string{
				{
					"cookie-persistence":           "mycookie",
					"cookie-persistence-no-dynamic": "mycookie",
				},
			},
			wantCookie: nil,
			wantErr:    true,
		},
		{
			name:        "no annotation clears cookie",
			annotations: []map[string]string{},
			wantCookie:  nil,
		},
		{
			// When the service annotation and the ingress annotation are present,
			// the service annotation takes priority (it is the first map in the slice).
			name: "service annotation wins over ingress annotation",
			annotations: []map[string]string{
				{"cookie-persistence": "service-cookie"},  // service annotation (highest priority)
				{"cookie-persistence": "ingress-cookie"},  // ingress annotation (lower priority)
			},
			wantCookie: expectedDynamicCookie("service-cookie"),
		},
		{
			// When only the ingress annotation is present (no service annotation),
			// the ingress annotation value is used.
			name: "ingress annotation used when service annotation absent",
			annotations: []map[string]string{
				{},                                        // empty service annotation
				{"cookie-persistence": "ingress-cookie"},  // ingress annotation
			},
			wantCookie: expectedDynamicCookie("ingress-cookie"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &models.Backend{}
			err := processCookie(backend, tt.annotations...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Cookie.Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(backend.Cookie, tt.wantCookie) {
				t.Errorf("Cookie.Process() backend.Cookie = %+v, want %+v", backend.Cookie, tt.wantCookie)
			}
		})
	}
}

// TestCookie_Process_MultiIngress_DifferentServices tests case 1 from the issue:
// Two ingresses pointing to different services with the same cookie-persistence value.
//
// Expected behaviour: each backend independently gets the cookie configured;
// there is no conflict because the backends are distinct.
func TestCookie_Process_MultiIngress_DifferentServices(t *testing.T) {
	const cookieName = "mycookie"

	// Simulate Ingress A → Service A
	backendA := &models.Backend{}
	if err := processCookie(backendA, map[string]string{"cookie-persistence": cookieName}); err != nil {
		t.Fatalf("backend A: Cookie.Process() unexpected error: %v", err)
	}

	// Simulate Ingress B → Service B  (different backend, same cookie name)
	backendB := &models.Backend{}
	if err := processCookie(backendB, map[string]string{"cookie-persistence": cookieName}); err != nil {
		t.Fatalf("backend B: Cookie.Process() unexpected error: %v", err)
	}

	wantCookie := expectedDynamicCookie(cookieName)

	if !reflect.DeepEqual(backendA.Cookie, wantCookie) {
		t.Errorf("backend A: Cookie = %+v, want %+v", backendA.Cookie, wantCookie)
	}
	if !reflect.DeepEqual(backendB.Cookie, wantCookie) {
		t.Errorf("backend B: Cookie = %+v, want %+v", backendB.Cookie, wantCookie)
	}
}

// TestCookie_Process_MultiIngress_SameService_SameCookie tests case 2 from the issue:
// Two ingresses pointing to the same service with the same cookie-persistence value.
//
// Expected behaviour: the annotation is idempotent; applying the same value twice
// produces the same cookie configuration.
func TestCookie_Process_MultiIngress_SameService_SameCookie(t *testing.T) {
	const cookieName = "mycookie"
	ingressAnnotations := map[string]string{"cookie-persistence": cookieName}

	// Simulate Ingress A processing the shared backend.
	backend := &models.Backend{}
	if err := processCookie(backend, ingressAnnotations); err != nil {
		t.Fatalf("first pass: Cookie.Process() unexpected error: %v", err)
	}
	afterFirstPass := backend.Cookie

	// Simulate Ingress B processing the same backend (same cookie value).
	if err := processCookie(backend, ingressAnnotations); err != nil {
		t.Fatalf("second pass: Cookie.Process() unexpected error: %v", err)
	}

	if !reflect.DeepEqual(backend.Cookie, afterFirstPass) {
		t.Errorf("cookie changed after second pass with same annotation value: got %+v, want %+v", backend.Cookie, afterFirstPass)
	}

	wantCookie := expectedDynamicCookie(cookieName)
	if !reflect.DeepEqual(backend.Cookie, wantCookie) {
		t.Errorf("backend.Cookie = %+v, want %+v", backend.Cookie, wantCookie)
	}
}

// TestCookie_Process_MultiIngress_SameService_ConflictingCookies tests case 3 from the issue:
// Two ingresses pointing to the same service but with *different* cookie-persistence values.
//
// Current behaviour (confirmed bug): the second annotation silently overwrites the first
// without any warning or error. The last ingress to be processed wins.
//
// TODO: Once the conflict-detection fix is implemented, this test should be updated to
// verify that a warning is emitted (e.g. via a non-nil error or a logged warning) when
// two ingresses specify different cookie names for the same backend.
func TestCookie_Process_MultiIngress_SameService_ConflictingCookies(t *testing.T) {
	const (
		cookieNameA = "cookie-from-ingress-a"
		cookieNameB = "cookie-from-ingress-b"
	)

	backend := &models.Backend{}

	// Ingress A is processed first and sets its cookie.
	if err := processCookie(backend, map[string]string{"cookie-persistence": cookieNameA}); err != nil {
		t.Fatalf("first pass (ingress A): Cookie.Process() unexpected error: %v", err)
	}
	if backend.Cookie == nil || *backend.Cookie.Name != cookieNameA {
		t.Fatalf("after first pass: expected cookie name %q, got %+v", cookieNameA, backend.Cookie)
	}

	// Ingress B is processed afterwards with a *different* cookie name.
	// BUG: this silently overwrites the cookie set by Ingress A with no warning.
	if err := processCookie(backend, map[string]string{"cookie-persistence": cookieNameB}); err != nil {
		t.Fatalf("second pass (ingress B): Cookie.Process() unexpected error: %v", err)
	}

	// Confirm the current (buggy) behaviour: the last value wins.
	if backend.Cookie == nil || *backend.Cookie.Name != cookieNameB {
		t.Errorf("after second pass: expected cookie name %q (last writer wins), got %+v", cookieNameB, backend.Cookie)
	}
}
