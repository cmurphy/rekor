//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	ttypes "github.com/google/trillian/types"
	"github.com/spf13/viper"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc/codes"

	"github.com/sigstore/rekor/pkg/events"
	"github.com/sigstore/rekor/pkg/events/newentry"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki/identity"
	"github.com/sigstore/rekor/pkg/pubsub"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/tle"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func signEntry(ctx context.Context, signer signature.Signer, entry models.LogEntryAnon) ([]byte, error) {
	payload, err := entry.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshalling error: %w", err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(payload)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing error: %w", err)
	}
	signature, err := signer.SignMessage(bytes.NewReader(canonicalized), options.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("signing error: %w", err)
	}
	return signature, nil
}

func getArtifactHashValue(entry types.EntryImpl) crypto.Hash {
	artifactHash, err := entry.ArtifactHash()
	if err != nil {
		// Default to SHA256 if no artifact hash is specified
		return crypto.SHA256
	}

	var artifactHashAlgorithm string
	algoPosition := strings.Index(artifactHash, ":")
	if algoPosition != -1 {
		artifactHashAlgorithm = artifactHash[:algoPosition]
	}
	switch artifactHashAlgorithm {
	case "sha256":
		return crypto.SHA256
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

func getPublicKey(identity identity.Identity) (crypto.PublicKey, error) {
	switch identityCrypto := identity.Crypto.(type) {
	case *x509.Certificate:
		return identityCrypto.PublicKey, nil
	case *rsa.PublicKey:
		return identityCrypto, nil
	case *ecdsa.PublicKey:
		return identityCrypto, nil
	case ed25519.PublicKey:
		return identityCrypto, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", identityCrypto)
	}
}

func checkEntryAlgorithms(entry types.EntryImpl) (bool, error) {
	// Only check algorithms for hashedrekord entries
	switch entry.(type) {
	case *hashedrekord.V001Entry:
		break
	default:
		return true, nil
	}

	verifiers, err := entry.Verifiers()
	if err != nil {
		return false, err
	}

	artifactHashValue := getArtifactHashValue(entry)

	// Check if all the verifiers public keys (together with the
	// artifactHashValue) are allowed according to the policy
	for _, v := range verifiers {
		identities, err := v.Identities()
		if err != nil {
			return false, err
		}

		for _, identity := range identities {
			publicKey, err := getPublicKey(identity)
			if err != nil {
				return false, err
			}
			isPermitted, err := api.algorithmRegistry.IsAlgorithmPermitted(publicKey, artifactHashValue)
			if err != nil {
				return false, fmt.Errorf("checking if algorithm is permitted: %w", err)
			}
			if !isPermitted {
				return false, nil
			}
		}
	}
	return true, nil
}

func createLogEntry(params entries.CreateLogEntryParams) (models.LogEntry, middleware.Responder) {
	ctx := params.HTTPRequest.Context()
	entry, err := types.CreateVersionedEntry(params.ProposedEntry)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf(validationError, err))
	}

	areEntryAlgorithmsAllowed, err := checkEntryAlgorithms(entry)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf(validationError, err))
	}
	if !areEntryAlgorithmsAllowed {
		return nil, handleRekorAPIError(params, http.StatusBadRequest, errors.New("entry algorithms are not allowed"), fmt.Sprintf(validationError, "entry algorithms are not allowed"))
	}

	leaf, err := types.CanonicalizeEntry(ctx, entry)
	if err != nil {
		var validationErr *types.InputValidationError
		if errors.As(err, &validationErr) {
			return nil, handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf(validationError, err))
		}
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, failedToGenerateCanonicalEntry)
	}

	tc := trillianclient.NewTrillianClient(ctx, api.logClient, api.treeID)

	resp := tc.AddLeaf(leaf)
	// this represents overall GRPC response state (not the results of insertion into the log)
	if resp.Status != codes.OK {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.Err), trillianUnexpectedResult)
	}

	// this represents the results of inserting the proposed leaf into the log; status is nil in success path
	insertionStatus := resp.GetAddResult.QueuedLeaf.Status
	if insertionStatus != nil {
		switch insertionStatus.Code {
		case int32(code.Code_OK):
		case int32(code.Code_ALREADY_EXISTS), int32(code.Code_FAILED_PRECONDITION):
			existingUUID := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(leaf))
			activeTree := fmt.Sprintf("%x", api.treeID)
			entryIDstruct, err := sharding.CreateEntryIDFromParts(activeTree, existingUUID)
			if err != nil {
				err := fmt.Errorf("error creating EntryID from active treeID %v and uuid %v: %w", activeTree, existingUUID, err)
				return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, fmt.Sprintf(validationError, err))
			}
			existingEntryID := entryIDstruct.ReturnEntryIDString()
			err = fmt.Errorf("grpc error: %v", insertionStatus.String())
			return nil, handleRekorAPIError(params, http.StatusConflict, err, fmt.Sprintf(entryAlreadyExists, existingEntryID), "entryURL", getEntryURL(*params.HTTPRequest.URL, existingEntryID))
		default:
			err := fmt.Errorf("grpc error: %v", insertionStatus.String())
			return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
		}
	}

	// We made it this far, that means the entry was successfully added.
	metricNewEntries.Inc()

	queuedLeaf := resp.GetAddResult.QueuedLeaf.Leaf

	uuid := hex.EncodeToString(queuedLeaf.GetMerkleLeafHash())
	activeTree := fmt.Sprintf("%x", api.treeID)
	entryIDstruct, err := sharding.CreateEntryIDFromParts(activeTree, uuid)
	if err != nil {
		err := fmt.Errorf("error creating EntryID from active treeID %v and uuid %v: %w", activeTree, uuid, err)
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, fmt.Sprintf(validationError, err))
	}
	entryID := entryIDstruct.ReturnEntryIDString()

	// The log index should be the virtual log index across all shards
	virtualIndex := sharding.VirtualLogIndex(queuedLeaf.LeafIndex, api.logRanges.GetActive().TreeID, api.logRanges)
	logEntryAnon := models.LogEntryAnon{
		LogID:          swag.String(api.logRanges.GetActive().LogID),
		LogIndex:       swag.Int64(virtualIndex),
		Body:           queuedLeaf.GetLeafValue(),
		IntegratedTime: swag.Int64(queuedLeaf.IntegrateTimestamp.AsTime().Unix()),
	}

	signature, err := signEntry(ctx, api.logRanges.GetActive().Signer, logEntryAnon)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("signing entry error: %w", err), signingError)
	}

	root := &ttypes.LogRootV1{}
	if err := root.UnmarshalBinary(resp.GetLeafAndProofResult.SignedLogRoot.LogRoot); err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("error unmarshalling log root: %w", err), sthGenerateError)
	}
	hashes := []string{}
	for _, hash := range resp.GetLeafAndProofResult.Proof.Hashes {
		hashes = append(hashes, hex.EncodeToString(hash))
	}

	scBytes, err := util.CreateAndSignCheckpoint(ctx, viper.GetString("rekor_server.hostname"), api.treeID, root.TreeSize, root.RootHash, api.logRanges.GetActive().Signer)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, sthGenerateError)
	}

	inclusionProof := models.InclusionProof{
		TreeSize:   swag.Int64(int64(root.TreeSize)),
		RootHash:   swag.String(hex.EncodeToString(root.RootHash)),
		LogIndex:   swag.Int64(queuedLeaf.LeafIndex),
		Hashes:     hashes,
		Checkpoint: swag.String(string(scBytes)),
	}

	logEntryAnon.Verification = &models.LogEntryAnonVerification{
		InclusionProof:       &inclusionProof,
		SignedEntryTimestamp: strfmt.Base64(signature),
	}

	logEntry := models.LogEntry{
		entryID: logEntryAnon,
	}

	if api.newEntryPublisher != nil {
		// Publishing notifications should not block the API response.
		go func() {
			verifiers, err := entry.Verifiers()
			if err != nil {
				incPublishEvent(newentry.Name, "", false)
				log.ContextLogger(ctx).Errorf("Could not get verifiers for log entry %s: %v", entryID, err)
				return
			}
			var subjects []string
			for _, v := range verifiers {
				subjects = append(subjects, v.Subjects()...)
			}

			pbEntry, err := tle.GenerateTransparencyLogEntry(logEntryAnon)
			if err != nil {
				incPublishEvent(newentry.Name, "", false)
				log.ContextLogger(ctx).Error(err)
				return
			}
			event, err := newentry.New(entryID, pbEntry, subjects)
			if err != nil {
				incPublishEvent(newentry.Name, "", false)
				log.ContextLogger(ctx).Error(err)
				return
			}
			if viper.GetBool("rekor_server.publish_events_protobuf") {
				go publishEvent(ctx, api.newEntryPublisher, event, events.ContentTypeProtobuf)
			}
			if viper.GetBool("rekor_server.publish_events_json") {
				go publishEvent(ctx, api.newEntryPublisher, event, events.ContentTypeJSON)
			}
		}()
	}

	return logEntry, nil
}

func publishEvent(ctx context.Context, publisher pubsub.Publisher, event *events.Event, contentType events.EventContentType) {
	err := publisher.Publish(context.WithoutCancel(ctx), event, contentType)
	incPublishEvent(event.Type().Name(), contentType, err == nil)
	if err != nil {
		log.ContextLogger(ctx).Error(err)
	}
}

func incPublishEvent(event string, contentType events.EventContentType, ok bool) {
	status := "SUCCESS"
	if !ok {
		status = "ERROR"
	}
	labels := map[string]string{
		"event":        event,
		"status":       status,
		"content_type": string(contentType),
	}
	metricPublishEvents.With(labels).Inc()
}

// CreateLogEntryHandler creates new entry into log
func CreateLogEntryHandler(params entries.CreateLogEntryParams) middleware.Responder {
	httpReq := params.HTTPRequest

	logEntry, err := createLogEntry(params)
	if err != nil {
		return err
	}

	var uuid string
	for location := range logEntry {
		uuid = location
	}

	return entries.NewCreateLogEntryCreated().WithPayload(logEntry).WithLocation(getEntryURL(*httpReq.URL, uuid)).WithETag(uuid)
}

// getEntryURL returns the absolute path to the log entry in a RESTful style
func getEntryURL(locationURL url.URL, uuid string) strfmt.URI {
	// remove API key from output
	query := locationURL.Query()
	query.Del("apiKey")
	locationURL.RawQuery = query.Encode()
	locationURL.Path = fmt.Sprintf("%v/%v", locationURL.Path, uuid)
	return strfmt.URI(locationURL.String())

}

var ErrNotFound = errors.New("grpc returned 0 leaves with success code")

// handlers for APIs that may be disabled in a given instance

func CreateLogEntryNotImplementedHandler(_ entries.CreateLogEntryParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Create Entry API not enabled in this Rekor instance",
	}

	return entries.NewCreateLogEntryDefault(http.StatusNotImplemented).WithPayload(err)
}
