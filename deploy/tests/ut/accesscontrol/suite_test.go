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
	"testing"

	"github.com/haproxytech/kubernetes-ingress/pkg/annotations"
	c "github.com/haproxytech/kubernetes-ingress/pkg/controller"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/env"
	"github.com/haproxytech/kubernetes-ingress/pkg/ingress"
	k8ssync "github.com/haproxytech/kubernetes-ingress/pkg/k8s/sync"
	"github.com/haproxytech/kubernetes-ingress/pkg/store"
	"github.com/haproxytech/kubernetes-ingress/pkg/utils"
	"github.com/jessevdk/go-flags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type FakeUpdateStatusManager struct{}

func (m *FakeUpdateStatusManager) AddIngress(ingress *ingress.Ingress) {}
func (m *FakeUpdateStatusManager) Update(k store.K8s, h haproxy.HAProxy, a annotations.Annotations) (err error) {
	return err
}

type AccessControlSuite struct {
	suite.Suite
	test Test
}

func TestAccessControl(t *testing.T) {
	suite.Run(t, new(AccessControlSuite))
}

type Test struct {
	Controller *c.HAProxyController
	TempDir    string
}

func (suite *AccessControlSuite) BeforeTest(suiteName, testName string) {
	tempDir, err := os.MkdirTemp("", "ut-"+testName+"-*")
	if err != nil {
		suite.T().Fatalf("Suite '%s': Test '%s' : error : %s", suiteName, testName, err)
	}
	suite.test.TempDir = tempDir
	suite.T().Logf("temporary configuration dir %s", suite.test.TempDir)
}

func (suite *AccessControlSuite) TearDownSuite() {
	_ = os.Unsetenv("POD_NAME")
}

// UseAccessControlFixture sets up a controller with an ingress that has the given annotations.
func (suite *AccessControlSuite) UseAccessControlFixture(ingressAnnotations map[string]string) (eventChan chan k8ssync.SyncDataEvent) {
	var osArgs utils.OSArgs
	os.Args = []string{os.Args[0], "-e", "-t", "--config-dir=" + suite.test.TempDir}
	parser := flags.NewParser(&osArgs, flags.IgnoreUnknown)
	_, errParsing := parser.Parse() //nolint:ifshort
	if errParsing != nil {
		suite.T().Fatal(errParsing)
	}

	s := store.NewK8sStore(osArgs)
	_ = os.Setenv("POD_NAME", "haproxy-kubernetes-ingress-68c9fc6d86-zn9qz")

	haproxyEnv := env.Env{
		CfgDir: suite.test.TempDir,
		Proxies: env.Proxies{
			FrontHTTP:  "http",
			FrontHTTPS: "https",
			FrontSSL:   "ssl",
			BackSSL:    "ssl-backend",
		},
	}
	haproxyConfig, err := os.ReadFile("../../../../fs/usr/local/etc/haproxy/haproxy.cfg")
	if err != nil {
		//nolint:testifylint
		assert.Failf(suite.T(), "error in opening init haproxy configuration file", err.Error())
	}

	eventChan = make(chan k8ssync.SyncDataEvent, watch.DefaultChanSize*6)
	controller := c.NewBuilder().
		WithHaproxyCfgFile(haproxyConfig).
		WithEventChan(eventChan).
		WithStore(s).
		WithHaproxyEnv(haproxyEnv).
		WithUpdateStatusManager(&FakeUpdateStatusManager{}).
		WithArgs(osArgs).Build()

	go controller.Start()

	// Now sending store events for test setup
	ns := store.Namespace{Name: "ns", Status: store.ADDED}
	eventChan <- k8ssync.SyncDataEvent{SyncType: k8ssync.NAMESPACE, Namespace: ns.Name, Data: &ns}

	endpoints := &store.Endpoints{
		SliceName: "myappservice",
		Service:   "myappservice",
		Namespace: ns.Name,
		Ports: map[string]*store.PortEndpoints{
			"http": {
				Port:      int64(8080),
				Addresses: map[string]struct{}{"10.244.0.9": {}},
			},
		},
		Status: store.ADDED,
	}
	eventChan <- k8ssync.SyncDataEvent{SyncType: k8ssync.ENDPOINTS, Namespace: endpoints.Namespace, Data: endpoints}

	service := &store.Service{
		Name:      "myappservice",
		Namespace: ns.Name,
		Ports: []store.ServicePort{
			{
				Name:     "http",
				Protocol: "TCP",
				Port:     80,
				Status:   store.ADDED,
			},
		},
		Status: store.ADDED,
	}
	eventChan <- k8ssync.SyncDataEvent{SyncType: k8ssync.SERVICE, Namespace: service.Namespace, Data: service}

	ingressClass := &store.IngressClass{
		Name:       "haproxy",
		Controller: "haproxy.org/ingress-controller",
		Status:     store.ADDED,
	}
	eventChan <- k8ssync.SyncDataEvent{SyncType: k8ssync.INGRESS_CLASS, Data: ingressClass}

	ing := &store.Ingress{
		IngressCore: store.IngressCore{
			APIVersion:  store.NETWORKINGV1,
			Name:        "myapping",
			Namespace:   ns.Name,
			Class:       "haproxy",
			Annotations: ingressAnnotations,
			Rules: map[string]*store.IngressRule{
				"": {
					Paths: map[string]*store.IngressPath{
						string(networkingv1.PathTypePrefix) + "-/": {
							Path:          "/",
							PathTypeMatch: string(networkingv1.PathTypePrefix),
							SvcNamespace:  service.Namespace,
							SvcPortString: "http",
							SvcName:       service.Name,
						},
					},
				},
			},
		},
		Status: store.ADDED,
	}

	eventChan <- k8ssync.SyncDataEvent{SyncType: k8ssync.INGRESS, Namespace: ing.Namespace, Data: ing}
	controllerHasWorked := make(chan struct{})
	eventChan <- k8ssync.SyncDataEvent{SyncType: k8ssync.COMMAND}
	eventChan <- k8ssync.SyncDataEvent{EventProcessed: controllerHasWorked}
	<-controllerHasWorked
	return eventChan
}
