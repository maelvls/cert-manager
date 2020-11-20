/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package policies

import (
	"context"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
)

func TestDataForCertificate(t *testing.T) {
	tests := []struct {
		name           string
		givenGetSecret func(t *testing.T) func(string) (*v1.Secret, error)
		givenListReq   func(t *testing.T) func(labels.Selector) ([]*cmapi.CertificateRequest, error)
		givenCrt       *cmapi.Certificate
		want           Input
		wantErr        string
	}{
		{
			name:           "the returned secret should stay nil when it is not found",
			givenCrt:       &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "secret-1"}, ObjectMeta: metav1.ObjectMeta{Name: "a"}},
			givenGetSecret: mockGetSecret("secret-1", nil, apierrors.NewNotFound(cmapi.Resource("Secret"), "secret-1")),
			givenListReq:   mockListCR([]*cmapi.CertificateRequest{}, nil),
			want:           Input{Secret: nil},
		},
		{
			name:           "should return an error when getsecret returns an unexpected error",
			givenCrt:       &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "secret-1"}, ObjectMeta: metav1.ObjectMeta{Name: "a"}},
			givenGetSecret: mockGetSecret("secret-1", nil, fmt.Errorf("unexpected")),
			givenListReq:   mockListCR([]*cmapi.CertificateRequest{}, nil),
			wantErr:        "unkexpected",
		},
		{
			name:           "the returned certificaterequest should stay nil when the list function returns nothing",
			givenCrt:       &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Name: "mycert"}},
			givenGetSecret: mockGetSecret("", nil, nil),
			givenListReq:   mockListCR([]*cmapi.CertificateRequest{}, nil),
			want:           Input{CurrentRevisionRequest: nil},
		},
		{
			name:           "should find the certificaterequest that matches revision and owner",
			givenCrt:       &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{UID: "uid-7"}, Status: cmapi.CertificateStatus{Revision: ptr(7)}},
			givenGetSecret: mockGetSecret("", nil, nil),
			givenListReq: mockListCR([]*cmapi.CertificateRequest{
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-4", Controller: &True}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "4"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-7", Controller: &True}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "7"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-9", Controller: &True}}}},
			}, nil),
			want: Input{CurrentRevisionRequest: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-7", Controller: &True}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "7"}},
			}},
		},
		{
			name:           "should return a nil cretificaterequest when no match of revision or owner",
			givenCrt:       &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}, Status: cmapi.CertificateStatus{Revision: ptr(1)}},
			givenGetSecret: mockGetSecret("", nil, nil),
			givenListReq: mockListCR([]*cmapi.CertificateRequest{
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: &True}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "2"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: &True}}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1"}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "1"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-42"}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "1"}}},
			}, nil),
			want: Input{CurrentRevisionRequest: nil},
		},
		{
			name:           "should return the cretificaterequest with revision 1 when certificate has no revision yet",
			givenCrt:       &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}, Status: cmapi.CertificateStatus{Revision: nil}},
			givenGetSecret: mockGetSecret("", nil, nil),
			givenListReq: mockListCR([]*cmapi.CertificateRequest{
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: &True}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "1"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: &True}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "2"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: &True}}}},
			}, nil),
			want: Input{CurrentRevisionRequest: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: &True}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "1"}},
			}},
		},
		{
			name: "should return the cretificaterequest and secret and both found",
			givenCrt: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{UID: "uid-1"},
				Spec:       cmapi.CertificateSpec{SecretName: "secret-1"},
				Status:     cmapi.CertificateStatus{Revision: ptr(1)},
			},
			givenGetSecret: mockGetSecret("secret-1", &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret-1"}}, nil),
			givenListReq: mockListCR([]*cmapi.CertificateRequest{
				{ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: &True}},
					Annotations:     map[string]string{"cert-manager.io/certificate-revision": "1"}},
				},
			}, nil),
			want: Input{
				CurrentRevisionRequest: &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: &True}},
					Annotations:     map[string]string{"cert-manager.io/certificate-revision": "1"}},
				},
				Secret: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret-1"}},
			},
		},
		{
			name:           "should return error when multiple cretificaterequests found",
			givenCrt:       &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}, Status: cmapi.CertificateStatus{Revision: ptr(1)}},
			givenGetSecret: mockGetSecret("", nil, nil),
			givenListReq: mockListCR([]*cmapi.CertificateRequest{
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: &True}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "1"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: &True}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "1"}}},
			}, nil),
			want:    Input{},
			wantErr: "multiple CertificateRequest resources exist for the current revision, not triggering new issuance until requests have been cleaned up",
		},
		{
			name:           "should return error when the list func returns an error",
			givenCrt:       &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}, Status: cmapi.CertificateStatus{Revision: ptr(1)}},
			givenGetSecret: mockGetSecret("", nil, nil),
			givenListReq:   mockListCR([]*cmapi.CertificateRequest{}, fmt.Errorf("unexpected")),
			want:           Input{},
			wantErr:        "unexpected",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := DataForCertificate(context.Background(), tt.givenGetSecret(t), tt.givenListReq(t), tt.givenCrt)

			if tt.wantErr != "" {
				assert.Error(t, gotErr, tt.wantErr)
				return
			}

			require.NoError(t, gotErr)
			assert.Equal(t, tt.want.CurrentRevisionRequest, got.CurrentRevisionRequest)
			assert.Equal(t, tt.want.Secret, got.Secret)
			assert.Equal(t, tt.givenCrt, got.Certificate, "input cert should always be equal to returned cert")
		})
	}
}

// mockAfterSelector is the list of certificate requests that have been
// returned by the List function.
func mockListCR(mockList []*cmapi.CertificateRequest, mockErr error) func(t *testing.T) func(labels.Selector) ([]*cmapi.CertificateRequest, error) {
	return func(t *testing.T) func(labels.Selector) ([]*cmapi.CertificateRequest, error) {
		return func(got labels.Selector) ([]*cmapi.CertificateRequest, error) {
			assert.Equal(t, "", got.String(), "since we use labels.Everything()")
			return mockList, mockErr
		}
	}
}

func mockGetSecret(expectedName string, mockSecret *v1.Secret, mockErr error) func(*testing.T) func(string) (*v1.Secret, error) {
	return func(t *testing.T) func(string) (*v1.Secret, error) {
		return func(gotName string) (*v1.Secret, error) {
			assert.Equal(t, expectedName, gotName)
			return mockSecret, mockErr
		}
	}
}

func ptr(i int) *int {
	return &i
}

var True = true
