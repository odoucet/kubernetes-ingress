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

package cookiepersistence

import (
	"log"
	"os"
	"path/filepath"
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
	"github.com/stretchr/testify/suite"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/watch"
)

// testHAProxyConfig is read once before any test so that the os.Chdir call
// inside controller.Start() cannot affect subsequent reads.
var testHAProxyConfig []byte

// TestMain reads the haproxy config file before the suite starts so that the
// os.Chdir performed inside controller.Start() does not affect file lookups.
func TestMain(m *testing.M) {
	var err error
	testHAProxyConfig, err = os.ReadFile("../../../../fs/usr/local/etc/haproxy/haproxy.cfg")
	if err != nil {
		log.Fatalf("error opening init haproxy configuration file: %v", err)
	}
	os.Exit(m.Run())
}

type FakeUpdateStatusManager struct{}

func (m *FakeUpdateStatusManager) AddIngress(ingress *ingress.Ingress) {}
func (m *FakeUpdateStatusManager) Update(k store.K8s, h haproxy.HAProxy, a annotations.Annotations) (err error) {
	return err
}

type CookiePersistenceTestSuite struct {
	suite.Suite
	test Test
}

func TestCookiePersistence(t *testing.T) {
	suite.Run(t, new(CookiePersistenceTestSuite))
}

type Test struct {
	Controller *c.HAProxyController
	TempDir    string
}

// readConfig reads haproxy.cfg from the temp directory and returns its content.
func (t *Test) readConfig(tester interface{ Fatalf(format string, args ...any) }) string {
	contents, err := os.ReadFile(filepath.Join(t.TempDir, "haproxy.cfg"))
	if err != nil {
		tester.Fatalf("failed to read haproxy.cfg from %s: %v", t.TempDir, err)
	}
	return string(contents)
}

func (suite *CookiePersistenceTestSuite) BeforeTest(suiteName, testName string) {
	tempDir, err := os.MkdirTemp("", "ut-cookie-"+testName+"-*")
	if err != nil {
		suite.T().Fatalf("Suite '%s': Test '%s' : error : %s", suiteName, testName, err)
	}
	suite.test.TempDir = tempDir
	suite.T().Logf("temporary configuration dir %s", suite.test.TempDir)
}

func (suite *CookiePersistenceTestSuite) TearDownSuite() {
	_ = os.Unsetenv("POD_NAME")
}

// buildController sets up and starts a controller with the given osArgs and returns the event channel.
func (suite *CookiePersistenceTestSuite) buildController(extraArgs ...string) (chan k8ssync.SyncDataEvent, *c.HAProxyController) {
	var osArgs utils.OSArgs
	args := []string{os.Args[0], "-e", "-t", "--config-dir=" + suite.test.TempDir}
	args = append(args, extraArgs...)
	os.Args = args
	parser := flags.NewParser(&osArgs, flags.IgnoreUnknown)
	_, errParsing := parser.Parse()
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

	eventChan := make(chan k8ssync.SyncDataEvent, watch.DefaultChanSize*6)
	controller := c.NewBuilder().
		WithHaproxyCfgFile(testHAProxyConfig). // use pre-loaded config (see TestMain)
		WithEventChan(eventChan).
		WithStore(s).
		WithHaproxyEnv(haproxyEnv).
		WithUpdateStatusManager(&FakeUpdateStatusManager{}).
		WithArgs(osArgs).Build()

	go controller.Start()
	return eventChan, controller
}

// sendIngressClass sends the shared "haproxy" IngressClass event.
func sendIngressClass(eventChan chan k8ssync.SyncDataEvent) {
	ingressClass := &store.IngressClass{
		Name:       "haproxy",
		Controller: "haproxy.org/ingress-controller",
		Status:     store.ADDED,
	}
	eventChan <- k8ssync.SyncDataEvent{SyncType: k8ssync.INGRESS_CLASS, Data: ingressClass}
}

// sendNamespace sends an ADDED namespace event.
func sendNamespace(eventChan chan k8ssync.SyncDataEvent, ns string) {
	namespace := store.Namespace{Name: ns, Status: store.ADDED}
	eventChan <- k8ssync.SyncDataEvent{SyncType: k8ssync.NAMESPACE, Namespace: ns, Data: &namespace}
}

// sendService sends an ADDED service event with a single HTTP port.
func sendService(eventChan chan k8ssync.SyncDataEvent, ns, svcName string) {
	svc := &store.Service{
		Name:        svcName,
		Namespace:   ns,
		Annotations: map[string]string{},
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
	eventChan <- k8ssync.SyncDataEvent{SyncType: k8ssync.SERVICE, Namespace: ns, Data: svc}
}

// sendEndpoints sends an ADDED endpoints event with one address.
func sendEndpoints(eventChan chan k8ssync.SyncDataEvent, ns, svcName, address string) {
	eps := &store.Endpoints{
		SliceName: svcName,
		Service:   svcName,
		Namespace: ns,
		Ports: map[string]*store.PortEndpoints{
			"http": {
				Port:      int64(80),
				Addresses: map[string]struct{}{address: {}},
			},
		},
		Status: store.ADDED,
	}
	eventChan <- k8ssync.SyncDataEvent{SyncType: k8ssync.ENDPOINTS, Namespace: ns, Data: eps}
}

// sendIngress sends an ADDED ingress event that routes all traffic to svcName in svcNS.
func sendIngress(eventChan chan k8ssync.SyncDataEvent, ingressNS, ingressName, host, svcNS, svcName string, annotations map[string]string) {
	ing := &store.Ingress{
		IngressCore: store.IngressCore{
			APIVersion:  store.NETWORKINGV1,
			Name:        ingressName,
			Namespace:   ingressNS,
			Class:       "haproxy",
			Annotations: annotations,
			Rules: map[string]*store.IngressRule{
				host: {
					Host: host,
					Paths: map[string]*store.IngressPath{
						string(networkingv1.PathTypePrefix) + "-/": {
							Path:          "/",
							PathTypeMatch: string(networkingv1.PathTypePrefix),
							SvcNamespace:  svcNS,
							SvcPortString: "http",
							SvcName:       svcName,
						},
					},
				},
			},
		},
		Status: store.ADDED,
	}
	eventChan <- k8ssync.SyncDataEvent{SyncType: k8ssync.INGRESS, Namespace: ingressNS, Data: ing}
}

// waitForController sends a COMMAND and EventProcessed and waits for the controller to finish.
func waitForController(eventChan chan k8ssync.SyncDataEvent) {
	done := make(chan struct{})
	eventChan <- k8ssync.SyncDataEvent{SyncType: k8ssync.COMMAND}
	eventChan <- k8ssync.SyncDataEvent{EventProcessed: done}
	<-done
}
