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
	"github.com/jetstack/cert-manager/pkg/controller/certificates"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/predicate"
)

var (
	Conflict = errors.New("found multiple certificate requests with the given revision and owner")
	NotFound = errors.New("found no certificate request with the given revision and owner")
)

// GetRelatedResources fetches the secret and "previous" certificate
// request associated with the given certificate. When not found, the
// returned secret and/or CR are simply left nil and no error is returned.
//
// To understand what this "previous" is about, see findPreviousCR.
func GetRelatedResources(
	ctx context.Context,
	getSecret func(string) (*v1.Secret, error),
	listCRs func(labels.Selector) ([]*cmapi.CertificateRequest, error),
	cert *cmapi.Certificate,
) (*v1.Secret, *cmapi.CertificateRequest, error) {
	log := logf.FromContext(ctx)

	secret, err := getSecret(cert.Spec.SecretName)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, nil, err
	}

	cr, err := findPreviousCR(listCRs, cert)
	switch {
	case err == Conflict:
		return nil, nil, fmt.Errorf("multiple CertificateRequest resources exist for the current revision, not triggering new issuance until requests have been cleaned up")
	case err == NotFound:
		log.V(logf.DebugLevel).Info("Found no CertificateRequest resources owned by this Certificate for the current revision", "revision", cert.Status.Revision)
	case err != nil:
		return nil, nil, err
	}

	return secret, cr, nil
}

// findPreviousCR retrieves the previous certificate request associated
// with the given certificate. By previous, we mean that this certificate
// request is the one that led to the current certificate becoming ready.
//
// Since there is no "previous" certificate request during the first
// issuance of the certificate, this function will return a nil certificate
// request.
//
// We need to be able to retrieve the "previous" certificate request
// because it is our only chance to check whether the current certificate
// still matches the already-issued certificate request. If the certificate
// request still matches the certificate, it won't have to be re-issued. If
// the user makes changes to the certificate spec, the "previous"
// certificate request will not match the certificate, leading to a
// re-issuance.
//
// This function returns a NotFound error when no CR is found, and returns
// Conflict when two CRs or more have been found for the certificate's
// revision.
func findPreviousCR(listCRs func(labels.Selector) ([]*cmapi.CertificateRequest, error), crt *cmapi.Certificate) (*cmapi.CertificateRequest, error) {
	// There is no previous request if the revision in the certificate's
	// status is nil. Keep in mind that the revision is set "at the very
	// end" of the certificate creation, i.e., after the incumbant
	// certificate request becomes ready.
	if crt.Status.Revision == nil {
		return nil, nil
	}
	reqs, err := certificates.ListCertificateRequestsMatchingPredicates(listCRs,
		labels.Everything(),
		predicate.ResourceOwnedBy(crt),
		predicate.CertificateRequestRevision(*crt.Status.Revision),
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
