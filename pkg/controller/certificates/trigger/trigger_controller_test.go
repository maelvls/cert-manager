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

package trigger

import (
	"context"
	"fmt"
	"testing"
	"time"

	logtest "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	internaltest "github.com/jetstack/cert-manager/pkg/controller/certificates/internal/test"
	"github.com/jetstack/cert-manager/pkg/controller/certificates/trigger/policies"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func Test_controller_ProcessItem(t *testing.T) {
	fixedNow := metav1.NewTime(time.Now())

	tests := map[string]struct {
		// key that should be passed to ProcessItem. If not set, the
		// 'namespace/name' of the 'Certificate' field will be used. If neither
		// is set, the key will be "".
		key string

		// Certificate to be synced for the test. if not set, the 'key' will be
		// passed to ProcessItem instead.
		existingCertificate *cmapi.Certificate

		mockDataForCertificateReturn    policies.Input
		mockDataForCertificateReturnErr error
		wantDataForCertificateCalled    bool

		mockShouldReissue       func(t *testing.T) policies.ShouldReissue
		wantShouldReissueCalled bool

		// wantEvent, if set, is an 'event string' that is expected to be fired.
		// For example, "Normal Issuing Re-issuance forced by unit test case"
		// where 'Normal' is the event severity, 'Issuing' is the reason and the
		// remainder is the message.
		wantEvent string

		// wantConditions is the expected set of conditions on the Certificate
		// resource if an Update is made.
		// If nil, no update is expected.
		// If empty, an update to the empty set/nil is expected.
		wantConditions []cmapi.CertificateCondition

		// wantErr is the expected error text returned by the controller, if any.
		wantErr string
	}{
		"do nothing if an empty 'key' is used": {},
		"do nothing if an invalid 'key' is used": {
			key: "abc/def/ghi",
		},
		"do nothing if a key references a Certificate that does not exist": {
			key: "namespace/name",
		},
		"do nothing if Certificate already has 'Issuing' condition": {
			existingCertificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", Generation: 3},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{
						{
							Type:               "Issuing",
							Status:             "True",
							ObservedGeneration: 3,
						},
					},
				}},
		},
		"should call shouldReissue with the correct cert, secret, next CR, and current CR": {
			existingCertificate: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateSecretName("test-secret"),
				gen.SetCertificateGeneration(42),
				gen.SetCertificateUID("uid"),
				gen.SetCertificateRevision(2),
			),
			wantDataForCertificateCalled: true,
			mockDataForCertificateReturn: policies.Input{
				Secret: gen.Secret("test-secret", gen.SetSecretNamespace("testns")),
				CurrentRevisionRequest: gen.CertificateRequest("test", gen.SetCertificateRequestNamespace("testns"),
					gen.SetCertificateRequestAnnotations(map[string]string{"cert-manager.io/certificate-revision": "2"}),
					gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("uid")),
				),
				NextRevisionRequest: gen.CertificateRequest("test", gen.SetCertificateRequestNamespace("testns"),
					gen.SetCertificateRequestAnnotations(map[string]string{"cert-manager.io/certificate-revision": "3"}),
					gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("uid")),
				),
			},
			wantShouldReissueCalled: true,
			mockShouldReissue: func(t *testing.T) policies.ShouldReissue {
				return func(gotInput policies.Input) (string, string, bool) {
					expectInput := policies.Input{
						Certificate: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
							gen.SetCertificateSecretName("test-secret"),
							gen.SetCertificateRevision(2),
							gen.SetCertificateGeneration(42),
							gen.SetCertificateUID("uid"),
						),
						CurrentRevisionRequest: gen.CertificateRequest("test", gen.SetCertificateRequestNamespace("testns"),
							gen.SetCertificateRequestAnnotations(map[string]string{"cert-manager.io/certificate-revision": "2"}),
							gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("uid")),
						),
						NextRevisionRequest: gen.CertificateRequest("test", gen.SetCertificateRequestNamespace("testns"),
							gen.SetCertificateRequestAnnotations(map[string]string{"cert-manager.io/certificate-revision": "3"}),
							gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("uid")),
						),
						Secret: gen.Secret("test-secret", gen.SetSecretNamespace("testns")),
					}
					assert.Equal(t, expectInput, gotInput)
					return "", "", false
				}
			},
		},
		"should log error when dataForCertificate errors": {
			existingCertificate:             gen.Certificate("test", gen.SetCertificateNamespace("testns")),
			wantDataForCertificateCalled:    true,
			mockDataForCertificateReturnErr: fmt.Errorf("dataForCertificate failed"),
			wantErr:                         "dataForCertificate failed",
		},
		"should set Issuing=True if shouldReissue tells us to reissue": {
			existingCertificate: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateGeneration(42),
			),
			wantDataForCertificateCalled: true,
			mockDataForCertificateReturn: policies.Input{},
			wantShouldReissueCalled:      true,
			mockShouldReissue: func(*testing.T) policies.ShouldReissue {
				return func(policies.Input) (string, string, bool) {
					return "ForceTriggered", "Re-issuance forced by unit test case", true
				}
			},
			wantEvent: "Normal Issuing Re-issuance forced by unit test case",
			wantConditions: []cmapi.CertificateCondition{{
				Type:               "Issuing",
				Status:             "True",
				Reason:             "ForceTriggered",
				Message:            "Re-issuance forced by unit test case",
				LastTransitionTime: &fixedNow,
				ObservedGeneration: 42,
			}},
		},
		"should set Issuing=True when cert does not match the CR and the cert has been failing for less than 60 minutes": {
			existingCertificate: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(fixedNow.Add(-59*time.Minute))),
				gen.SetCertificateCommonName("example-cn"),
				gen.SetCertificateGeneration(42),
				gen.SetCertificateUID("uid"),
				gen.SetCertificateRevision(3),
			),
			wantDataForCertificateCalled: true,
			mockDataForCertificateReturn: policies.Input{
				NextRevisionRequest: createCertificateRequestOrPanic(gen.Certificate("test", gen.SetCertificateNamespace("testns"),
					gen.SetCertificateCommonName("example-cn-updated"),
					gen.SetCertificateUID("uid"),
					gen.SetCertificateRevision(4),
				)),
			},
			wantShouldReissueCalled: true,
			mockShouldReissue: func(*testing.T) policies.ShouldReissue {
				return func(policies.Input) (string, string, bool) {
					return "ForceTriggered", "Re-issuance forced by unit test case", true
				}
			},
			wantEvent: "Normal Issuing Re-issuance forced by unit test case",
			wantConditions: []cmapi.CertificateCondition{{
				Type:               "Issuing",
				Status:             "True",
				Reason:             "ForceTriggered",
				Message:            "Re-issuance forced by unit test case",
				LastTransitionTime: &fixedNow,
				ObservedGeneration: 42,
			}},
		},
		"should not set Issuing=True when cert has been failing for less than 1 hour and cert still matches the CR": {
			existingCertificate: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(fixedNow.Add(-59*time.Minute))),
			),
			wantDataForCertificateCalled: true,
			mockDataForCertificateReturn: policies.Input{},
			wantShouldReissueCalled:      false,
		},
		"should set Issuing=True when cert has been failing for more than 1 hour and shouldReissue returns true": {
			existingCertificate: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateGeneration(42),
				gen.SetCertificateLastFailureTime(metav1.NewTime(fixedNow.Add(-61*time.Minute))),
			),
			wantDataForCertificateCalled: true,
			mockDataForCertificateReturn: policies.Input{},
			wantShouldReissueCalled:      true,
			mockShouldReissue: func(*testing.T) policies.ShouldReissue {
				return func(policies.Input) (string, string, bool) {
					return "ForceTriggered", "Re-issuance forced by unit test case", true
				}
			},
			wantEvent: "Normal Issuing Re-issuance forced by unit test case",
			wantConditions: []cmapi.CertificateCondition{{
				Type:               "Issuing",
				Status:             "True",
				Reason:             "ForceTriggered",
				Message:            "Re-issuance forced by unit test case",
				LastTransitionTime: &fixedNow,
				ObservedGeneration: 42,
			}},
		},
		"should set Issuing=True when mismatch between cert and next CR and cert just failed": {
			existingCertificate: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateLastFailureTime(fixedNow),
				gen.SetCertificateGeneration(42),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			),
			wantDataForCertificateCalled: true,
			mockDataForCertificateReturn: policies.Input{
				NextRevisionRequest: createCertificateRequestOrPanic(
					gen.Certificate("test", gen.SetCertificateNamespace("testns"),
						gen.SetCertificateUID("test-uid"),
						gen.SetCertificateRevision(2),
						gen.SetCertificateDNSNames("example2.com"), // Mismatch here.
					)),
			},
			wantShouldReissueCalled: true,
			mockShouldReissue: func(*testing.T) policies.ShouldReissue {
				return func(policies.Input) (string, string, bool) {
					return "ForceTriggered", "Re-issuance forced by unit test case", true
				}
			},
			wantEvent: "Normal Issuing Re-issuance forced by unit test case",
			wantConditions: []cmapi.CertificateCondition{{
				Type:               "Issuing",
				Status:             "True",
				Reason:             "ForceTriggered",
				Message:            "Re-issuance forced by unit test case",
				LastTransitionTime: &fixedNow,
				ObservedGeneration: 42,
			}},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			builder := &testpkg.Builder{
				T:     t,
				Clock: fakeclock.NewFakeClock(fixedNow.Time),
			}
			if test.existingCertificate != nil {
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.existingCertificate)
			}
			builder.Init()

			w := &controllerWrapper{}
			_, _, err := w.Register(builder.Context)
			if err != nil {
				t.Fatal(err)
			}

			gotShouldReissueCalled := false
			w.shouldReissue = func(i policies.Input) (string, string, bool) {
				gotShouldReissueCalled = true
				if test.mockShouldReissue == nil {
					t.Fatal("no mock set for shouldReissue, but shouldReissue has been called")
					return "", "", false
				} else {
					return test.mockShouldReissue(t)(i)
				}
			}

			// TODO(mael): we should really remove the Certificate field from
			// DataForCertificate since the input certificate is always expected
			// to be the same as the output certiticate.
			test.mockDataForCertificateReturn.Certificate = test.existingCertificate

			gotDataForCertificateCalled := false
			w.dataForCertificate = func(context.Context, *cmapi.Certificate) (policies.Input, error) {
				gotDataForCertificateCalled = true
				return test.mockDataForCertificateReturn, test.mockDataForCertificateReturnErr
			}

			if test.wantConditions != nil {
				if test.existingCertificate == nil {
					t.Fatal("cannot expect an Update operation if test.certificate is nil")
				}
				expectedCert := test.existingCertificate.DeepCopy()
				expectedCert.Status.Conditions = test.wantConditions
				builder.ExpectedActions = append(builder.ExpectedActions,
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						test.existingCertificate.Namespace,
						expectedCert,
					)),
				)
			}
			if test.wantEvent != "" {
				builder.ExpectedEvents = []string{test.wantEvent}
			}

			builder.Start()
			defer builder.Stop()

			key := test.key
			if key == "" && test.existingCertificate != nil {
				key, err = controllerpkg.KeyFunc(test.existingCertificate)
				if err != nil {
					t.Fatal(err)
				}
			}

			gotErr := w.controller.ProcessItem(context.Background(), key)
			switch {
			case gotErr != nil:
				if test.wantErr != gotErr.Error() {
					t.Errorf("error text did not match, got=%s, exp=%s", gotErr.Error(), test.wantErr)
				}
			default:
				if test.wantErr != "" {
					t.Errorf("got no error but expected: %s", test.wantErr)
				}
			}

			assert.Equal(t, test.wantDataForCertificateCalled, gotDataForCertificateCalled, "dataForCertificate func call")
			assert.Equal(t, test.wantShouldReissueCalled, gotShouldReissueCalled, "shouldReissue func call")

			builder.CheckAndFinish()
		})
	}
}

// We don't need to full bundle, just a simple CertificateRequest.
func createCertificateRequestOrPanic(crt *cmapi.Certificate) *cmapi.CertificateRequest {
	bundle, err := internaltest.CreateCryptoBundle(crt, fakeclock.NewFakeClock(time.Now()))
	if err != nil {
		panic(err)
	}
	return bundle.CertificateRequest
}

func Test_shouldBackoffReissuingOnFailure(t *testing.T) {
	clock := fakeclock.NewFakeClock(time.Date(2020, 11, 20, 16, 05, 00, 0000, time.Local))
	tests := map[string]struct {
		givenCert    *cmapi.Certificate
		givenRequest *cmapi.CertificateRequest
		wantBackoff  bool
		wantDelay    time.Duration
	}{
		"no need to backoff from reissuing when the input request is nil": {
			givenCert:   gen.Certificate("test", gen.SetCertificateNamespace("testns")),
			wantBackoff: false,
		},
		"no need to back off from reissuing when there is no previous failure": {
			givenCert: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example2.com"),
				gen.SetCertificateRevision(1),
				// LastFailureTime is not set here.
			),
			givenRequest: createCertificateRequestOrPanic(gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example2.com"),
				gen.SetCertificateRevision(1),
			)),
			wantBackoff: false,
		},
		"should not back off from reissuing when the certificate is failed but was updated and is now different from the certificate request ": {
			givenCert: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example42.com"), // This field was does not match the CR.
				gen.SetCertificateRevision(1),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-1*time.Minute))),
			),
			givenRequest: createCertificateRequestOrPanic(gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example2.com"),
				gen.SetCertificateRevision(1),
			)),
			wantBackoff: false,
		},
		"should not back off from reissuing when the failure happened 61 minutes ago": {
			givenCert: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example2.com"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-61*time.Minute))),
			),
			givenRequest: createCertificateRequestOrPanic(gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example2.com"),
				gen.SetCertificateRevision(1),
			)),
			wantBackoff: false,
		},
		"should back off from reissuing when the failure happened 59 minutes ago": {
			givenCert: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example2.com"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-59*time.Minute))),
			),
			givenRequest: createCertificateRequestOrPanic(gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example2.com"),
				gen.SetCertificateRevision(1),
			)),
			wantBackoff: true,
			wantDelay:   1 * time.Minute,
		},
		"should not back off from reissuing when the failure is more than an hour ago, reissuance can happen now": {
			givenCert: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example2.com"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-61*time.Minute))),
			),
			givenRequest: createCertificateRequestOrPanic(gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example2.com"),
				gen.SetCertificateRevision(1),
			)),
			wantBackoff: false,
		},
		"should not back off from reissuing when the failure happened exactly an hour ago": {
			givenCert: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example2.com"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-60*time.Minute))),
			),
			givenRequest: createCertificateRequestOrPanic(gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example2.com"),
				gen.SetCertificateRevision(1),
			)),
			wantBackoff: false,
		},
		"should back off from reissuing for the maximum of 1 hour when failure just happened": {
			givenCert: gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example2.com"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now())),
			),
			givenRequest: createCertificateRequestOrPanic(gen.Certificate("test", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("test-uid"),
				gen.SetCertificateDNSNames("example2.com"),
				gen.SetCertificateRevision(1),
			)),
			wantBackoff: true,
			wantDelay:   1 * time.Hour,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotBackoff, gotDelay := shouldBackoffReissuingOnFailure(logtest.TestLogger{T: t}, clock, test.givenCert, test.givenRequest)
			assert.Equal(t, test.wantBackoff, gotBackoff)
			assert.Equal(t, test.wantDelay, gotDelay)
		})
	}
}
