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
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"github.com/spf13/viper"
	logFormat "github.com/transparency-dev/formats/log"
	tessera "github.com/transparency-dev/trillian-tessera"
	"github.com/transparency-dev/trillian-tessera/api/layout"
	"github.com/transparency-dev/trillian-tessera/client"
	"google.golang.org/grpc/codes"

	"github.com/sigstore/rekor/pkg/events"
	"github.com/sigstore/rekor/pkg/events/newentry"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pubsub"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/tle"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	maxSearchQueries = 10
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

// logEntryFromLeaf creates a signed LogEntry struct from trillian structs
func logEntryFromLeaf(ctx context.Context, signer signature.Signer, leaf *trillian.LogLeaf,
	signedLogRoot *trillian.SignedLogRoot, proof *trillian.Proof, tid int64, ranges sharding.LogRanges) (models.LogEntry, error) {

	log.ContextLogger(ctx).Debugf("log entry from leaf %d", leaf.GetLeafIndex())
	root := &ttypes.LogRootV1{}
	if err := root.UnmarshalBinary(signedLogRoot.LogRoot); err != nil {
		return nil, err
	}
	hashes := []string{}
	for _, hash := range proof.Hashes {
		hashes = append(hashes, hex.EncodeToString(hash))
	}

	virtualIndex := sharding.VirtualLogIndex(leaf.GetLeafIndex(), tid, ranges)
	logEntryAnon := models.LogEntryAnon{
		LogID:          swag.String(api.pubkeyHash),
		LogIndex:       &virtualIndex,
		Body:           leaf.LeafValue,
		IntegratedTime: swag.Int64(leaf.IntegrateTimestamp.AsTime().Unix()),
	}

	signature, err := signEntry(ctx, signer, logEntryAnon)
	if err != nil {
		return nil, fmt.Errorf("signing entry error: %w", err)
	}

	scBytes, err := util.CreateAndSignCheckpoint(ctx, viper.GetString("rekor_server.hostname"), tid, root.TreeSize, root.RootHash, api.signer)
	if err != nil {
		return nil, err
	}

	inclusionProof := models.InclusionProof{
		TreeSize:   swag.Int64(int64(root.TreeSize)),
		RootHash:   swag.String(hex.EncodeToString(root.RootHash)),
		LogIndex:   swag.Int64(proof.GetLeafIndex()),
		Hashes:     hashes,
		Checkpoint: stringPointer(string(scBytes)),
	}

	uuid := hex.EncodeToString(leaf.MerkleLeafHash)
	treeID := fmt.Sprintf("%x", tid)
	entryIDstruct, err := sharding.CreateEntryIDFromParts(treeID, uuid)
	if err != nil {
		return nil, fmt.Errorf("error creating EntryID from active treeID %v and uuid %v: %w", treeID, uuid, err)
	}
	entryID := entryIDstruct.ReturnEntryIDString()

	logEntryAnon.Verification = &models.LogEntryAnonVerification{
		InclusionProof:       &inclusionProof,
		SignedEntryTimestamp: strfmt.Base64(signature),
	}

	return models.LogEntry{
		entryID: logEntryAnon}, nil
}

// GetLogEntryAndProofByIndexHandler returns the entry and inclusion proof for a specified log index
func GetLogEntryByIndexHandler(params entries.GetLogEntryByIndexParams) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	logEntry, err := retrieveLogEntryByIndex(ctx, int(params.LogIndex))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return handleRekorAPIError(params, http.StatusNotFound, fmt.Errorf("grpc error: %w", err), "")
		}
		return handleRekorAPIError(params, http.StatusInternalServerError, err, err.Error())
	}
	return entries.NewGetLogEntryByIndexOK().WithPayload(logEntry)
}

func createLogEntry(params entries.CreateLogEntryParams) (models.LogEntry, middleware.Responder) {
	ctx := params.HTTPRequest.Context()
	entry, err := types.CreateVersionedEntry(params.ProposedEntry)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf(validationError, err))
	}
	leaf, err := types.CanonicalizeEntry(ctx, entry)
	if err != nil {
		var validationErr *types.InputValidationError
		if errors.As(err, &validationErr) {
			return nil, handleRekorAPIError(params, http.StatusBadRequest, err, fmt.Sprintf(validationError, err))
		}
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, failedToGenerateCanonicalEntry)
	}

	tesseraEntry := tessera.NewEntry(leaf)
	idx, err := tesseraStorage.Add(params.HTTPRequest.Context(), tesseraEntry)()
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
	}

	// We made it this far, that means the entry was successfully added.
	metricNewEntries.Inc()

	logEntryAnon := models.LogEntryAnon{
		LogID:          swag.String(api.pubkeyHash),
		LogIndex:       swag.Int64(int64(idx)),
		Body:           leaf,
		IntegratedTime: swag.Int64(time.Now().Unix()), // FIXME: either don't require integrated time or find an authentic source for it
	}

	signature, err := signEntry(ctx, api.signer, logEntryAnon)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, sthGenerateError)
	}
	checkpointBody, err := tesseraStorage.ReadCheckpoint(context.TODO())
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, err.Error())
	}
	if checkpointBody == nil {
		return nil, handleRekorAPIError(params, http.StatusNotFound, err, "")
	}
	checkpoint := logFormat.Checkpoint{}
	_, err = checkpoint.Unmarshal(checkpointBody)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, err.Error())
	}
	scBytes, err := util.CreateAndSignCheckpoint(ctx, viper.GetString("rekor_server.hostname"), api.logID, checkpoint.Size, checkpoint.Hash, api.signer)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, sthGenerateError)
	}

	tileOnlyFetcher := func(ctx context.Context, path string) ([]byte, error) {
		pathParts := strings.SplitN(path, "/", 3)
		level, index, width, err := layout.ParseTileLevelIndexWidth(pathParts[1], pathParts[2])
		if err != nil {
			return nil, err
		}
		return tesseraStorage.ReadTile(ctx, level, index, width)
	}
	proofBuilder, err := client.NewProofBuilder(ctx, checkpoint, tileOnlyFetcher)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, sthGenerateError)
	}
	proof, err := proofBuilder.InclusionProof(ctx, idx)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, sthGenerateError)
	}
	hashes := make([]string, len(proof))
	for i, h := range proof {
		hashes[i] = hex.EncodeToString(h)
	}

	inclusionProof := models.InclusionProof{
		TreeSize:   swag.Int64(int64(checkpoint.Size)),
		RootHash:   swag.String(hex.EncodeToString(checkpoint.Hash)),
		LogIndex:   swag.Int64(int64(idx)),
		Hashes:     hashes,
		Checkpoint: swag.String(string(scBytes)),
	}

	logEntryAnon.Verification = &models.LogEntryAnonVerification{
		InclusionProof:       &inclusionProof,
		SignedEntryTimestamp: strfmt.Base64(signature),
	}

	uuid := hex.EncodeToString(tesseraEntry.LeafHash())
	logEntry := models.LogEntry{
		uuid: logEntryAnon,
	}

	if api.newEntryPublisher != nil {
		// Publishing notifications should not block the API response.
		go func() {
			verifiers, err := entry.Verifiers()
			if err != nil {
				incPublishEvent(newentry.Name, "", false)
				log.ContextLogger(ctx).Errorf("Could not get verifiers for log entry %s: %v", uuid, err)
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
			event, err := newentry.New(uuid, pbEntry, subjects)
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

func retrieveLogEntryByIndex(ctx context.Context, logIndex int) (models.LogEntry, error) {
	log.ContextLogger(ctx).Infof("Retrieving log entry by index %d", logIndex)

	tid, resolvedIndex := api.logRanges.ResolveVirtualIndex(logIndex)
	tc := trillianclient.NewTrillianClient(ctx, api.logClient, tid) // FIXME:tessera
	log.ContextLogger(ctx).Debugf("Retrieving resolved index %v from TreeID %v", resolvedIndex, tid)

	resp := tc.GetLeafAndProofByIndex(resolvedIndex) // FIXME:tessera
	switch resp.Status {
	case codes.OK:
	case codes.NotFound, codes.OutOfRange, codes.InvalidArgument:
		return models.LogEntry{}, ErrNotFound
	default:
		return models.LogEntry{}, fmt.Errorf("grpc err: %w: %s", resp.Err, trillianCommunicationError)
	}

	result := resp.GetLeafAndProofResult
	leaf := result.Leaf
	if leaf == nil {
		return models.LogEntry{}, ErrNotFound
	}

	return logEntryFromLeaf(ctx, api.signer, leaf, result.SignedLogRoot, result.Proof, tid, api.logRanges)
}

// handlers for APIs that may be disabled in a given instance

func CreateLogEntryNotImplementedHandler(_ entries.CreateLogEntryParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Create Entry API not enabled in this Rekor instance",
	}

	return entries.NewCreateLogEntryDefault(http.StatusNotImplemented).WithPayload(err)
}

func GetLogEntryByIndexNotImplementedHandler(_ entries.GetLogEntryByIndexParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Get Log Entry by Index API not enabled in this Rekor instance",
	}

	return entries.NewGetLogEntryByIndexDefault(http.StatusNotImplemented).WithPayload(err)
}
