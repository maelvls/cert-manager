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
	"errors"
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

var (
	Conflict = errors.New("found multiple certificate requests with the given revision and owner")
	NotFound = errors.New("found no certificate request with the given revision and owner")
)

// GetRelatedResources fetches the Secret and CertificateRequest associated
// with the given Certificate. When not found, the returned Secret and/or
// CR are simply left nil and no error is returned.
func GetRelatedResources(ctx context.Context, getSecret func(string) (*v1.Secret, error), listCR cmlisters.CertificateRequestNamespaceLister, crt *cmapi.Certificate) (*v1.Secret, *cmapi.CertificateRequest, error) {
	log := logf.FromContext(ctx)

	secret, err := getSecret(crt.Spec.SecretName)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, nil, err
	}

	cr, err := findPreviousCR(listCR, crt)
	switch {
	case err == Conflict:
		return nil, nil, fmt.Errorf("multiple CertificateRequest resources exist for the current revision, not triggering new issuance until requests have been cleaned up")
	case err == NotFound:
		log.V(logf.DebugLevel).Info("Found no CertificateRequest resources owned by this Certificate for the current revision", "revision", crt.Status.Revision)
	case err != nil:
		return nil, nil, err
	}

	return secret, cr, nil
}

// findCurrentCR retrieves the current certificate request associated with
// the given certificate.
//
// A CertificateRequest is associated to a given
// certificate when both:
// (1) the CR is owned by the certificate, and
// (2) the CR contains an annotation that matches the certificate's
// status.revision, or "1" when status.revision is nil.
//
// This function returns a NotFound error when no CR is found, and returns
// Conflict when two CRs or more have been found for the certificate's
// revision.
func findPreviousCR(lister cmlisters.CertificateRequestNamespaceLister, crt *cmapi.Certificate) (*cmapi.CertificateRequest, error) {
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
		return nil, err
	}

	var req *cmapi.CertificateRequest
	switch {
	case len(reqs) > 1:
		return nil, Conflict
	case len(reqs) == 0:
		// We use a custom error because we cannot use errors.NewNotFound.
		// That is due to the fact that errors.NewNotFound needs to be
		// given a specific object name. Here, we don't know the name of
		// the CertificateRequest.
		return nil, NotFound
	case len(reqs) == 1:
		req = reqs[0]
	}

	return req, nil
}
