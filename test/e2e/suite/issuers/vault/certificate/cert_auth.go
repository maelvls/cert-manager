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

package certificate

import (
	"context"
	"path"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/framework/addon"
	vaultaddon "github.com/cert-manager/cert-manager/test/e2e/framework/addon/vault"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/validation"
	"github.com/cert-manager/cert-manager/test/e2e/util"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var _ = framework.CertManagerDescribe("Vault Cert Auth should work", func() {
	fs := featureset.NewFeatureSet(featureset.SaveRootCAToSecret)
	runVaultCertAuthTest(fs)
})

func runVaultCertAuthTest(fs featureset.FeatureSet) {
	f := framework.NewDefaultFramework("create-vault-cert")
	vault := &vaultaddon.Vault{
		Base: addon.Base,
		Name: "vault-cert-auth",
	}

	BeforeEach(func() {
		vault.Namespace = f.Namespace.Name
	})

	f.RequireAddon(vault)

	rootMount := "root-ca"
	intermediateMount := "intermediate-ca"
	authPath := "cert"
	role := "cert"
	certificateName := "test-vault"
	certificateSecretName := "test-vault"
	vaultPath := path.Join(intermediateMount, "sign", role)
	var vaultIssuerName, vaultSecretNamespace string
	var keyPEM, certPEM []byte
	var vaultSecretName string

	var vaultInit *vaultaddon.VaultInitializer

	BeforeEach(func() {
		vaultSecretNamespace = f.Namespace.Name
		vaultInit = &vaultaddon.VaultInitializer{
			Details:           *vault.Details(),
			RootMount:         rootMount,
			IntermediateMount: intermediateMount,
			Role:              role,
			CertAuthPath:      authPath,
		}
		err := vaultInit.Init()
		Expect(err).NotTo(HaveOccurred())
		err = vaultInit.Setup()
		Expect(err).NotTo(HaveOccurred())
		keyPEM, certPEM, err = vaultInit.CreateCertRole()
		Expect(err).NotTo(HaveOccurred())

		sec, err := f.KubeClientSet.CoreV1().Secrets(vaultSecretNamespace).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "vault-client-cert"},
			StringData: map[string]string{
				"tls.key": string(keyPEM),
				"tls.crt": string(certPEM),
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		vaultSecretName = sec.Name
	})

	JustAfterEach(func() {
		By("Cleaning up")
		Expect(vaultInit.Clean()).NotTo(HaveOccurred())
		f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.TODO(), vaultIssuerName, metav1.DeleteOptions{})

		f.KubeClientSet.CoreV1().Secrets(vaultSecretNamespace).Delete(context.TODO(), vaultSecretName, metav1.DeleteOptions{})
	})

	It("should generate a new valid certificate", func() {
		By("Creating an Issuer")
		vaultURL := vault.Details().Host

		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		vaultIssuer := gen.IssuerWithRandomName("test-vault-issuer-",
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerVaultURL(vaultURL),
			gen.SetIssuerVaultPath(vaultPath),
			gen.SetIssuerVaultCABundle(vault.Details().VaultCA),
			gen.SetClientCertificateAuth(&cmapi.VaultClientCertificateAuth{
				Path:       "/v1/auth/" + authPath,
				Name:       role,
				SecretName: vaultSecretName,
			}))
		iss, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), vaultIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		vaultIssuerName = iss.Name

		By("Waiting for Issuer to become Ready")

		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			vaultIssuerName,
			cmapi.IssuerCondition{
				Type:   cmapi.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})

		Expect(err).NotTo(HaveOccurred())

		By("Creating a Certificate")
		cert, err := certClient.Create(context.TODO(), util.NewCertManagerVaultCertificate(certificateName, certificateSecretName, vaultIssuerName, "Issuer", nil, nil), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be issued...")
		cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(cert, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Validating the issued Certificate...")
		err = f.Helper().ValidateCertificate(cert, validation.CertificateSetForUnsupportedFeatureSet(fs)...)
		Expect(err).NotTo(HaveOccurred())
	})
}
