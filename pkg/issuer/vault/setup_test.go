/*
Copyright 2022 The cert-manager Authors.

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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	vaultinternal "github.com/cert-manager/cert-manager/internal/vault"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmfake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	"github.com/cert-manager/cert-manager/pkg/controller"
	testlisters "github.com/cert-manager/cert-manager/test/unit/listers"
)

func TestVault_Setup(t *testing.T) {
	// Create a mock Vault HTTP server.
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/approle/login" || r.URL.Path == "/v1/auth/kubernetes/login":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"auth":{"client_token": "5b1a0318-679c-9c45-e5c6-d1b9a9035d49"}}`))
		}
	}))
	defer vaultServer.Close()

	type test struct {
		givenIssuer      v1.IssuerConfig
		expectCond       string
		expectErr        string
		mockGetSecret    *corev1.Secret
		mockGetSecretErr error
	}
	run := func(tt test) func(t *testing.T) {
		return func(t *testing.T) {
			givenIssuer := &v1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "test-namespace",
				},
				Spec: v1.IssuerSpec{
					IssuerConfig: tt.givenIssuer,
				},
			}
			cmclient := cmfake.NewSimpleClientset(givenIssuer)

			v := &Vault{
				issuer:            givenIssuer,
				Context:           &controller.Context{CMClient: cmclient},
				resourceNamespace: "test-namespace",
				createTokenFn: func(ns string) vaultinternal.CreateToken {
					return func(ctx context.Context, saName string, req *authv1.TokenRequest, opts metav1.CreateOptions) (*authv1.TokenRequest, error) {
						return &authv1.TokenRequest{Status: authv1.TokenRequestStatus{
							Token: "token",
						}}, nil
					}
				},
				secretsLister: &testlisters.FakeSecretLister{
					SecretsFn: func(namespace string) corelisters.SecretNamespaceLister {
						return &testlisters.FakeSecretNamespaceLister{
							GetFn: func(name string) (ret *corev1.Secret, err error) {
								assert.Equal(t, "cert-manager", name)
								assert.Equal(t, "test-namespace", namespace)
								return &corev1.Secret{
									ObjectMeta: metav1.ObjectMeta{Name: "cert-manager", Namespace: "test-namespace"},
									Data:       map[string][]byte{"token": []byte("root")},
								}, nil
							},
						}
					},
				},
			}

			err := v.Setup(context.Background())
			if tt.expectErr != "" {
				assert.EqualError(t, err, tt.expectErr)
				return
			}
			assert.NoError(t, err)

			if tt.expectCond != "" {
				require.Len(t, givenIssuer.Status.Conditions, 1)
				assert.Equal(t, tt.expectCond, fmt.Sprintf("%s %s: %s: %s", givenIssuer.Status.Conditions[0].Type, givenIssuer.Status.Conditions[0].Status, givenIssuer.Status.Conditions[0].Reason, givenIssuer.Status.Conditions[0].Message))
			} else {
				require.Len(t, givenIssuer.Status.Conditions, 0)
			}
		}
	}

	t.Run("developer mistake: the vault field is empty", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: nil,
		},
		expectCond: "Ready False: VaultError: Vault config cannot be empty",
	}))
	t.Run("path is missing", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{
				Server: "https://vault.example.com",
			},
		},
		expectCond: "Ready False: VaultError: Vault server and path are required fields",
	}))
	t.Run("server is missing", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{
				Path: "pki_int",
			},
		},
		expectCond: "Ready False: VaultError: Vault server and path are required fields",
	}))
	t.Run("auth.appRole, auth.kubernetes, and auth.tokenSecretRef are mutually exclusive", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{

				Path:   "pki_int",
				Server: "https://vault.example.com",
				Auth: v1.VaultAuth{
					AppRole: &v1.VaultAppRole{
						SecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
						},
					},
					Kubernetes: &v1.VaultKubernetesAuth{
						SecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
						},
						Path: "kubernetes",
						Role: "cert-manager",
					},
					TokenSecretRef: &cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "cert-manager",
						},
						Key: "token",
					},
				},
			},
		},
		expectCond: "Ready False: VaultError: Multiple auth methods cannot be set on the same Vault issuer",
	}))
	t.Run("valid auth.appRole", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{
				Path:   "pki_int",
				Server: vaultServer.URL,
				Auth: v1.VaultAuth{
					AppRole: &v1.VaultAppRole{
						RoleId: "cert-manager",
						SecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
							Key: "token",
						},
						Path: "approle",
					},
				},
			},
		},
		expectCond: "Ready True: VaultVerified: Vault verified",
	}))
	t.Run("auth.appRole.secretRef.key can be left empty, but an error will show", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{
				Path:   "pki_int",
				Server: "https://vault.example.com",
				Auth: v1.VaultAuth{
					AppRole: &v1.VaultAppRole{
						RoleId: "cert-manager",
						SecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
						},
						Path: "approle",
					},
				},
			},
		},
		expectErr: `no data for "" in secret 'test-namespace/cert-manager'`,
	}))
	t.Run("auth.appRole.roleId is missing", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{
				Path:   "pki_int",
				Server: "https://vault.example.com",
				Auth: v1.VaultAuth{
					AppRole: &v1.VaultAppRole{
						SecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
						},
					},
				},
			},
		},
		expectCond: "Ready False: VaultError: Vault AppRole auth requires both roleId and tokenSecretRef.name",
	}))
	t.Run("auth.appRole.secretRef.name is missing", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{
				Path:   "pki_int",
				Server: "https://vault.example.com",
				Auth: v1.VaultAuth{
					AppRole: &v1.VaultAppRole{
						RoleId: "cert-manager",
					},
				},
			},
		},
		expectCond: "Ready False: VaultError: Vault AppRole auth requires both roleId and tokenSecretRef.name",
	}))
	t.Run("valid auth.kubernetes.secretRef", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{
				Path:   "pki_int",
				Server: vaultServer.URL,
				Auth: v1.VaultAuth{
					Kubernetes: &v1.VaultKubernetesAuth{
						Role: "cert-manager",
						SecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
							Key: "token",
						},
					},
				},
			},
		},
		expectCond: "Ready True: VaultVerified: Vault verified",
	}))
	t.Run("auth.kubernetes.secretRef.name is missing", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{
				Path:   "pki_int",
				Server: "https://vault.example.com",
				Auth: v1.VaultAuth{
					Kubernetes: &v1.VaultKubernetesAuth{
						Role: "cert-manager",
					},
				},
			},
		},
		expectCond: "Ready False: VaultError: Vault Kubernetes auth requires both role and secretRef.name",
	}))
	t.Run("auth.kubernetes.secretRef.key can be left empty and defaults to 'token'", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{
				Path:   "pki_int",
				Server: vaultServer.URL,
				Auth: v1.VaultAuth{
					Kubernetes: &v1.VaultKubernetesAuth{
						Role: "cert-manager",
						SecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
						},
					},
				},
			},
		},
		expectCond: "Ready True: VaultVerified: Vault verified",
	}))
	t.Run("valid auth.kubernetes.role", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{
				Path:   "pki_int",
				Server: "https://vault.example.com",
				Auth: v1.VaultAuth{
					Kubernetes: &v1.VaultKubernetesAuth{
						Role: "cert-manager",
						SecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
						},
					},
				},
			},
		},
		expectCond: "Ready False: VaultError: Vault Kubernetes auth requires both role and secretRef.name",
	}))
	t.Run("auth.kubernetes.role is missing", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{
				Path:   "pki_int",
				Server: "https://vault.example.com",
				Auth: v1.VaultAuth{
					Kubernetes: &v1.VaultKubernetesAuth{
						SecretRef: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "cert-manager",
							},
						},
					},
				},
			},
		},
		expectCond: "Ready False: VaultError: Vault Kubernetes auth requires both role and secretRef.name",
	}))
	t.Run("valid auth.tokenSecretRef", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{
				Path:   "pki_int",
				Server: vaultServer.URL,
				Auth: v1.VaultAuth{
					TokenSecretRef: &cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "cert-manager",
						},
						Key: "token",
					},
				},
			},
		},
		expectCond: "Ready True: VaultVerified: Vault verified",
	}))
	t.Run("auth.tokenSecretRef.key can be left empty and defaults to 'token'", run(test{
		givenIssuer: v1.IssuerConfig{
			Vault: &v1.VaultIssuer{
				Path:   "pki_int",
				Server: vaultServer.URL,
				Auth: v1.VaultAuth{
					TokenSecretRef: &cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "cert-manager",
						},
					},
				},
			},
		},
		expectCond: "Ready True: VaultVerified: Vault verified",
	}))
}
