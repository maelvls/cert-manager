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

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/controller/certificates"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/predicate"
)

// DataForCertificate is used to gather data about a Certificate in order
// to evaluate its current readiness/state by applying policy functions to
// it.
//
// The returned input.CurrentRevisionRequest and input.Secret are left nil
// when they cannot be found. The input.Certificate is copied as-is from
// the given crt.
func DataForCertificate(ctx context.Context, getSecret func(string) (*v1.Secret, error), lister cmlisters.CertificateRequestNamespaceLister, crt *cmapi.Certificate) (Input, error) {
	log := logf.FromContext(ctx)
	// Attempt to fetch the Secret being managed but tolerate NotFound errors.
	secret, err := getSecret(crt.Spec.SecretName)
	if err != nil && !apierrors.IsNotFound(err) {
		return Input{}, err
	}

	// Fetch the CertificateRequest resource for the current
	// 'status.revision' if it exists; default to using revision "1" since
	// the issuing controller may be still issuing the first revision of
	// the certificate.
	revision := 1
	if crt.Status.Revision != nil {
		revision = *crt.Status.Revision
	}
	reqs, err := certificates.ListCertificateRequestsMatchingPredicates(lister,
		labels.Everything(),
		predicate.ResourceOwnedBy(crt),
		predicate.CertificateRequestRevision(revision),
	)
	if err != nil {
		return Input{}, err
	}

	var req *cmapi.CertificateRequest
	switch {
	case len(reqs) > 1:
		return Input{}, fmt.Errorf("multiple CertificateRequest resources exist for the current revision, not triggering new issuance until requests have been cleaned up")
	case len(reqs) == 1:
		req = reqs[0]
	case len(reqs) == 0:
		log.V(logf.DebugLevel).Info("Found no CertificateRequest resources owned by this Certificate for the current revision", "revision", revision)
	}

	return Input{
		Certificate:            crt,
		CurrentRevisionRequest: req,
		Secret:                 secret,
	}, nil
}
