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

package vault

import (
	"context"
	"fmt"

	"github.com/cert-manager/cert-manager/internal/apis/certmanager/validation"
	vaultinternal "github.com/cert-manager/cert-manager/internal/vault"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	successVaultVerified = "VaultVerified"
	messageVaultVerified = "Vault verified"

	errorVault = "VaultError"

	messageVaultClientInitFailed         = "Failed to initialize Vault client: "
	messageVaultStatusVerificationFailed = "Vault is not initialized or is sealed"
	messageVaultConfigRequired           = "Vault config cannot be empty"
	messageServerAndPathRequired         = "Vault server and path are required fields"
	messageAuthFieldsRequired            = "Vault tokenSecretRef, appRole, or kubernetes is required"
	messageMultipleAuthFieldsSet         = "Multiple auth methods cannot be set on the same Vault issuer"

	messageKubeAuthRoleRequired      = "Vault Kubernetes auth requires a role to be set"
	messageKubeAuthEitherRequired    = "Vault Kubernetes auth requires either secretRef.name or serviceAccountRef to be set"
	messageKubeAuthSingleRequired    = "Vault Kubernetes auth cannot be used with both secretRef.name and serviceAccountRef.name"
	messageTokenAuthNameRequired     = "Vault Token auth requires tokenSecretRef.name"
	messageAppRoleAuthFieldsRequired = "Vault AppRole auth requires both roleId and tokenSecretRef.name"
)

// Setup creates a new Vault client and attempts to authenticate with the Vault instance and sets the issuer's conditions to reflect the success of the setup.
func (v *Vault) Setup(ctx context.Context) error {
	if v.issuer.GetSpec().Vault == nil {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageVaultConfigRequired)
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageVaultConfigRequired)
		return nil
	}

	v1.Convert_v1_Issuer_To_certmanager_Issuer(v.issuer.GetSpec().Vault)
	err := validation.ValidateVaultIssuer(v.issuer.GetSpec().Vault, field.NewPath("spec", "vault"))

	createTokenFn := func(ns string) vaultinternal.CreateToken { return v.Client.CoreV1().ServiceAccounts(ns).CreateToken }
	client, err := vaultinternal.New(v.resourceNamespace, createTokenFn, v.secretsLister, v.issuer)
	if err != nil {
		s := messageVaultClientInitFailed + err.Error()
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, s)
		return err
	}

	if err := client.IsVaultInitializedAndUnsealed(); err != nil {
		logf.V(logf.WarnLevel).Infof("%s: %s: error: %s", v.issuer.GetObjectMeta().Name, messageVaultStatusVerificationFailed, err.Error())
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageVaultStatusVerificationFailed)
		return fmt.Errorf(messageVaultStatusVerificationFailed)
	}

	logf.Log.V(logf.DebugLevel).Info(messageVaultVerified)
	apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionTrue, successVaultVerified, messageVaultVerified)
	return nil
}
