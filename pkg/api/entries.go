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
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/spf13/viper"
	tessera "github.com/transparency-dev/trillian-tessera"
	tesseraapi "github.com/transparency-dev/trillian-tessera/api"

	"github.com/sigstore/rekor/pkg/events"
	"github.com/sigstore/rekor/pkg/events/newentry"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pubsub"
	rekortessera "github.com/sigstore/rekor/pkg/tessera"
	"github.com/sigstore/rekor/pkg/tle"
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

// GetLogEntryAndProofByIndexHandler returns the entry and inclusion proof for a specified log index
func GetLogEntryByIndexHandler(params entries.GetLogEntryByIndexParams) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	logEntry, err := retrieveLogEntryByIndex(ctx, params.TreeID, int(params.LogIndex))
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
	tesseraStorage, err := api.tesseraClient.Connect(ctx, params.TreeID)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, tesseraCommunicationError)
	}

	idx, err := tesseraStorage.Add(params.HTTPRequest.Context(), tesseraEntry)()
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, tesseraUnexpectedResult)
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

	checkpoint, err := rekortessera.GetLatestCheckpoint(ctx, tesseraStorage)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, err.Error())
	}
	scBytes, err := util.CreateAndSignCheckpoint(ctx, viper.GetString("rekor_server.hostname"), params.TreeID, checkpoint.Size, checkpoint.Hash, api.signer)
	if err != nil {
		return nil, handleRekorAPIError(params, http.StatusInternalServerError, err, sthGenerateError)
	}

	proofBuilder, err := rekortessera.ProofBuilder(ctx, checkpoint, tesseraStorage)
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

func retrieveLogEntryByIndex(ctx context.Context, treeID string, logIndex int) (models.LogEntry, error) {
	log.ContextLogger(ctx).Infof("Retrieving log entry by index %d", logIndex)

	tesseraStorage, err := api.tesseraClient.Connect(ctx, treeID)
	if err != nil {
		return models.LogEntry{}, err
	}
	entryBundle, err := tesseraStorage.ReadEntryBundle(ctx, uint64(logIndex/256), 0)
	if err != nil {
		return models.LogEntry{}, err
	}
	if entryBundle == nil {
		return models.LogEntry{}, ErrNotFound
	}
	bundle := tesseraapi.EntryBundle{}
	if err := bundle.UnmarshalText(entryBundle); err != nil {
		return models.LogEntry{}, err
	}
	if logIndex%256 >= len(bundle.Entries) {
		return models.LogEntry{}, ErrNotFound
	}
	entry := bundle.Entries[logIndex%256]

	tesseraEntry := tessera.NewEntry(entry)

	logEntryAnon := models.LogEntryAnon{
		LogID:          swag.String(api.pubkeyHash),
		LogIndex:       swag.Int64(int64(logIndex)),
		Body:           entry,
		IntegratedTime: swag.Int64(time.Now().Unix()), // FIXME
	}

	signature, err := signEntry(ctx, api.signer, logEntryAnon)
	if err != nil {
		return models.LogEntry{}, err
	}

	checkpoint, err := rekortessera.GetLatestCheckpoint(ctx, tesseraStorage)
	if err != nil {
		return models.LogEntry{}, fmt.Errorf("reading checkpoint: %w", err)
	}
	scBytes, err := util.CreateAndSignCheckpoint(ctx, viper.GetString("rekor_server.hostname"), treeID, checkpoint.Size, checkpoint.Hash, api.signer)
	if err != nil {
		return models.LogEntry{}, err
	}
	proofBuilder, err := rekortessera.ProofBuilder(ctx, checkpoint, tesseraStorage)
	if err != nil {
		return models.LogEntry{}, fmt.Errorf("getting proof builder: %w", err)
	}
	proof, err := proofBuilder.InclusionProof(ctx, uint64(logIndex))
	if err != nil {
		return models.LogEntry{}, err
	}
	hashes := make([]string, len(proof))
	for i, h := range proof {
		hashes[i] = hex.EncodeToString(h)
	}

	inclusionProof := models.InclusionProof{
		TreeSize:   swag.Int64(int64(checkpoint.Size)),
		RootHash:   swag.String(hex.EncodeToString(checkpoint.Hash)),
		LogIndex:   swag.Int64(int64(logIndex)),
		Hashes:     hashes,
		Checkpoint: swag.String(string(scBytes)),
	}

	logEntryAnon.Verification = &models.LogEntryAnonVerification{
		InclusionProof:       &inclusionProof,
		SignedEntryTimestamp: strfmt.Base64(signature),
	}

	entryID := hex.EncodeToString(tesseraEntry.LeafHash())
	return models.LogEntry{
		entryID: logEntryAnon,
	}, nil
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
