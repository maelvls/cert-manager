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

package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientcorev1 "k8s.io/client-go/listers/core/v1"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests/util"
	controllertest "github.com/jetstack/cert-manager/pkg/controller/test"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
	"github.com/jetstack/cert-manager/test/unit/listers"
	testlisters "github.com/jetstack/cert-manager/test/unit/listers"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func generateCSR(t *testing.T, secretKey crypto.Signer) []byte {
	asn1Subj, _ := asn1.Marshal(pkix.Name{
		CommonName: "test",
	}.ToRDNSequence())
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, secretKey)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return csr
}

func generateSelfSignedCertFromCR(t *testing.T, cr *cmapi.CertificateRequest, key crypto.Signer,
	duration time.Duration) (*x509.Certificate, []byte) {
	template, err := pki.GenerateTemplateFromCertificateRequest(cr)
	if err != nil {
		t.Errorf("error generating template: %v", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Errorf("error signing cert: %v", err)
		t.FailNow()
	}

	pemByteBuffer := bytes.NewBuffer([]byte{})
	err = pem.Encode(pemByteBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		t.Errorf("failed to encode cert: %v", err)
		t.FailNow()
	}

	return template, pemByteBuffer.Bytes()
}

func TestSign(t *testing.T) {
	baseIssuer := gen.Issuer("test-issuer",
		gen.SetIssuerCA(cmapi.CAIssuer{SecretName: "root-ca-secret"}),
		gen.AddIssuerCondition(cmapi.IssuerCondition{
			Type:   cmapi.IssuerConditionReady,
			Status: cmmeta.ConditionTrue,
		}),
	)

	// Build root RSA CA
	skRSA, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	skRSAPEM := pki.EncodePKCS1PrivateKey(skRSA)
	rsaCSR := generateCSR(t, skRSA)

	baseCR := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestIsCA(true),
		gen.SetCertificateRequestCSR(rsaCSR),
		gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Name:  baseIssuer.DeepCopy().Name,
			Group: certmanager.GroupName,
			Kind:  "Issuer",
		}),
		gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour * 24 * 60}),
	)

	// generate a self signed root ca valid for 60d
	_, rsaPEMCert := generateSelfSignedCertFromCR(t, baseCR, skRSA, time.Hour*24*60)
	rsaCASecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "root-ca-secret",
			Namespace: gen.DefaultTestNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: skRSAPEM,
			corev1.TLSCertKey:       rsaPEMCert,
		},
	}

	badDataSecret := rsaCASecret.DeepCopy()
	badDataSecret.Data[corev1.TLSPrivateKeyKey] = []byte("bad key")

	template, err := pki.GenerateTemplateFromCertificateRequest(baseCR)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	certPEM, _, err := pki.SignCSRTemplate([]*x509.Certificate{template}, skRSA, template)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	metaFixedClockStart := metav1.NewTime(fixedClockStart)
	tests := map[string]testT{
		"a missing CA key pair should set the condition to pending and wait for a re-sync": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Normal SecretMissing Referenced secret default-unit-test-ns/root-ca-secret not found: secret "root-ca-secret" not found`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR.DeepCopy(),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            `Referenced secret default-unit-test-ns/root-ca-secret not found: secret "root-ca-secret" not found`,
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"a secret with invalid data should set condition to pending and wait for re-sync": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{badDataSecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(),
					gen.IssuerFrom(baseIssuer.DeepCopy(),
						gen.SetIssuerCA(cmapi.CAIssuer{SecretName: badDataSecret.Name}),
					),
				},
				ExpectedEvents: []string{
					"Normal SecretInvalidData Failed to parse signing CA keypair from secret default-unit-test-ns/root-ca-secret: error decoding private key PEM block",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR.DeepCopy(),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Failed to parse signing CA keypair from secret default-unit-test-ns/root-ca-secret: error decoding private key PEM block",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"a CertificateRequest that transiently fails a secret lookup should backoff error to retry": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rsaCASecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Normal SecretGetError Failed to get certificate key pair from secret default-unit-test-ns/root-ca-secret: this is a network error`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonPending,
								Message:            "Failed to get certificate key pair from secret default-unit-test-ns/root-ca-secret: this is a network error",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
			fakeLister: &testlisters.FakeSecretLister{
				SecretsFn: func(namespace string) clientcorev1.SecretNamespaceLister {
					return &testlisters.FakeSecretNamespaceLister{
						GetFn: func(name string) (ret *corev1.Secret, err error) {
							return nil, errors.New("this is a network error")
						},
					}
				},
			},
			expectedErr: true,
		},
		"should exit nil and set status pending if referenced issuer is not ready": {
			certificateRequest: baseCR.DeepCopy(),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{rsaCASecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(),
					gen.Issuer(baseIssuer.DeepCopy().Name,
						gen.SetIssuerCA(cmapi.CAIssuer{}),
					)},
				ExpectedEvents: []string{
					"Normal IssuerNotReady Referenced issuer does not have a Ready status condition",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             "Pending",
								Message:            "Referenced issuer does not have a Ready status condition",
								LastTransitionTime: &metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"a secret that fails to sign due to failing to generate the certificate template should set condition to failed": {
			certificateRequest: baseCR.DeepCopy(),
			templateGenerator: func(*cmapi.CertificateRequest) (*x509.Certificate, error) {
				return nil, errors.New("this is a template generate error")
			},
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rsaCASecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning SigningError Error generating certificate template: this is a template generate error",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR.DeepCopy(),
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionFalse,
								Reason:             cmapi.CertificateRequestReasonFailed,
								Message:            "Error generating certificate template: this is a template generate error",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestFailureTime(metaFixedClockStart),
						),
					)),
				},
			},
		},
		"a successful signing with ocspServers set should set condition to Ready": {
			certificateRequest: baseCR.DeepCopy(),
			templateGenerator: func(cr *cmapi.CertificateRequest) (*x509.Certificate, error) {
				_, err := pki.GenerateTemplateFromCertificateRequest(cr)
				if err != nil {
					return nil, err
				}

				return template, nil
			},
			builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rsaCASecret},
				CertManagerObjects: []runtime.Object{baseCR.DeepCopy(), baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"status",
						gen.DefaultTestNamespace,
						gen.CertificateRequestFrom(baseCR,
							gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:               cmapi.CertificateRequestConditionReady,
								Status:             cmmeta.ConditionTrue,
								Reason:             cmapi.CertificateRequestReasonIssued,
								Message:            "Certificate fetched from issuer successfully",
								LastTransitionTime: &metaFixedClockStart,
							}),
							gen.SetCertificateRequestCA(rsaPEMCert),
							gen.SetCertificateRequestCertificate(certPEM),
						),
					)),
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			test.builder.Clock = fixedClock
			runTest(t, test)
		})
	}
}

type testT struct {
	builder            *testpkg.Builder
	certificateRequest *cmapi.CertificateRequest
	templateGenerator  templateGenerator

	expectedErr bool

	fakeLister *testlisters.FakeSecretLister
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()
	defer test.builder.Stop()

	ca := NewCA(test.builder.Context)

	if test.fakeLister != nil {
		ca.secretsLister = test.fakeLister
	}

	if test.templateGenerator != nil {
		ca.templateGenerator = test.templateGenerator
	}

	controller := certificaterequests.New(apiutil.IssuerCA, ca)
	controller.Register(test.builder.Context)
	test.builder.Start()

	err := controller.Sync(context.Background(), test.certificateRequest)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	test.builder.CheckAndFinish(err)
}

func TestCA_Sign(t *testing.T) {
	caCrt, caKey := mustGenerateTLSAssets(t)
	// Build root RSA CA
	skRSA, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	skRSAPEM := pki.EncodePKCS1PrivateKey(skRSA)
	rsaCSR := generateCSR(t, skRSA)

	tests := map[string]struct {
		givenNamespace string
		givenSecret    *corev1.Secret
		givenCR        *cmapi.CertificateRequest
		givenIssuer    cmapi.GenericIssuer
		wantIssueResp  *issuer.IssueResponse
		wantErr        string
	}{
		"nil issue response when": {
			givenIssuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{
					CA: &cmapi.CAIssuer{
						SecretName:  "secret-1",
						OCSPServers: []string{"http://ocsp-v3.example.org"},
					},
				}},
			},
			givenCR: gen.CertificateRequestFrom(gen.CertificateRequest("cert-1")),
			givenSecret: gen.SecretFrom(gen.Secret("secret-1"),
				gen.SetSecretNamespace("default"),
				gen.SetSecretData(map[string][]byte{
					"tls.key": caKey,
					"tls.crt": caCrt,
				}),
			),
			givenNamespace: "default",
			wantIssueResp:  nil,
		},
		"issued": {
			givenIssuer: gen.Issuer("issuer-1", gen.SetIssuerCA(cmapi.CAIssuer{
				SecretName:  "secret-1",
				OCSPServers: []string{"http://ocsp-v3.example.org"},
			})),
			givenCR: gen.CertificateRequest("cr-1",
				gen.SetCertificateRequestIsCA(true),
				gen.SetCertificateRequestCSR(rsaCSR),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "issuer-1",
					Group: certmanager.GroupName,
					Kind:  "Issuer",
				}),
				gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour * 24 * 60}),
			),

			givenSecret: gen.SecretFrom(gen.Secret("secret-1"),
				gen.SetSecretNamespace("default"),
				gen.SetSecretData(map[string][]byte{
					"tls.key": caKey,
					"tls.crt": caCrt,
				}),
			),
			givenNamespace: "default",
			wantIssueResp:  nil,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &controllertest.FakeRecorder{}

			c := &CA{
				issuerOptions: controller.IssuerOptions{
					ClusterResourceNamespace:        "",
					ClusterIssuerAmbientCredentials: false,
					IssuerAmbientCredentials:        false,
				},
				reporter: util.NewReporter(fixedClock, rec),
				secretsLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
					listers.SetFakeSecretNamespaceListerGet(test.givenSecret, nil),
				),
				templateGenerator: pki.GenerateTemplateFromCertificateRequest,
			}

			gotIssueResp, gotErr := c.Sign(context.Background(), test.givenCR, test.givenIssuer)
			if test.wantErr != "" {
				assert.EqualError(t, gotErr, test.wantErr)
				return
			}
			require.NoError(t, gotErr)

			if test.wantIssueResp == nil {
				assert.Nil(t, gotIssueResp)
				return
			}

			gotCert, err := pki.DecodeX509CertificateBytes(gotIssueResp.Certificate)
			require.NoError(t, err)

			assert.Equal(t, test.wantIssueResp, gotCert)
		})
	}
}

// Returns a PEM-formated CA certificate and its key.
func mustGenerateTLSAssets(t *testing.T) (caCrt, caKey []byte) {
	caPK, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootCA := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1658),
		PublicKeyAlgorithm:    x509.RSA,
		Subject: pkix.Name{
			CommonName: "testing-ca",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		IsCA:      true,
	}
	rootCADER, err := x509.CreateCertificate(rand.Reader, rootCA, rootCA, caPK.Public(), caPK)
	require.NoError(t, err)
	rootCA, err = x509.ParseCertificate(rootCADER)
	require.NoError(t, err)

	// encoding PKI data to PEM
	caKey, err = pki.EncodePKCS8PrivateKey(caPK)
	require.NoError(t, err)
	caCrt, err = pki.EncodeX509(rootCA)
	require.NoError(t, err)

	return caCrt, caKey
}
