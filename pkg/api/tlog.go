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
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/google/trillian/types"
	"github.com/spf13/viper"
	logFormat "github.com/transparency-dev/formats/log"
	"google.golang.org/grpc/codes"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/tlog"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"github.com/sigstore/rekor/pkg/util"
)

// GetLogInfoHandler returns the current size of the tree and the STH
func GetLogInfoHandler(params tlog.GetLogInfoParams) middleware.Responder {
	checkpointBody, err := tesseraStorage.ReadCheckpoint(context.TODO())
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("checkpoint error: %w", err), "")
	}
	if checkpointBody == nil {
		return handleRekorAPIError(params, http.StatusNotFound, err, "")
	}
	var checkpoint logFormat.Checkpoint
	_, err = checkpoint.Unmarshal(checkpointBody)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, "")
	}

	scBytes, err := util.CreateAndSignCheckpoint(params.HTTPRequest.Context(),
		viper.GetString("rekor_server.hostname"), api.logRanges.ActiveTreeID(), checkpoint.Size, checkpoint.Hash, api.signer)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, sthGenerateError)
	}

	treeSize := int64(checkpoint.Size)
	hexHash := hex.EncodeToString(checkpoint.Hash)
	logInfo := models.LogInfo{
		RootHash:       stringPointer(hexHash),
		TreeSize:       &treeSize,
		SignedTreeHead: stringPointer(string(scBytes)),
		TreeID:         stringPointer(fmt.Sprintf("%d", api.logID)),
		//InactiveShards: inactiveShards,
	}

	return tlog.NewGetLogInfoOK().WithPayload(&logInfo)
}

func stringPointer(s string) *string {
	return &s
}

// GetLogProofHandler returns information required to compute a consistency proof between two snapshots of log
func GetLogProofHandler(params tlog.GetLogProofParams) middleware.Responder {
	if *params.FirstSize > params.LastSize {
		return handleRekorAPIError(params, http.StatusBadRequest, nil, fmt.Sprintf(firstSizeLessThanLastSize, *params.FirstSize, params.LastSize))
	}
	tc := trillianclient.NewTrillianClient(params.HTTPRequest.Context(), api.logClient, api.logID) // FIXME:tessera
	if treeID := swag.StringValue(params.TreeID); treeID != "" {
		id, err := strconv.Atoi(treeID)
		if err != nil {
			log.Logger.Infof("Unable to convert %s to string, skipping initializing client with Tree ID: %v", treeID, err)
		} else {
			tc = trillianclient.NewTrillianClient(params.HTTPRequest.Context(), api.logClient, int64(id)) // FIXME:tessera
		}
	}

	resp := tc.GetConsistencyProof(*params.FirstSize, params.LastSize) // FIXME:tessera
	if resp.Status != codes.OK {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.Err), trillianCommunicationError)
	}
	result := resp.GetConsistencyProofResult

	var root types.LogRootV1
	if err := root.UnmarshalBinary(result.SignedLogRoot.LogRoot); err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
	}

	hashString := hex.EncodeToString(root.RootHash)
	proofHashes := []string{}

	if proof := result.GetProof(); proof != nil {
		for _, hash := range proof.Hashes {
			proofHashes = append(proofHashes, hex.EncodeToString(hash))
		}
	} else {
		// The proof field may be empty if the requested tree_size was larger than that available at the server
		// (e.g. because there is skew between server instances, and an earlier client request was processed by
		// a more up-to-date instance). root.TreeSize is the maximum size currently observed
		err := fmt.Errorf(lastSizeGreaterThanKnown, params.LastSize, root.TreeSize)
		return handleRekorAPIError(params, http.StatusBadRequest, err, err.Error())
	}

	consistencyProof := models.ConsistencyProof{
		RootHash: &hashString,
		Hashes:   proofHashes,
	}

	return tlog.NewGetLogProofOK().WithPayload(&consistencyProof)
}

func inactiveShardLogInfo(ctx context.Context, tid int64) (*models.InactiveShardLogInfo, error) {
	tc := trillianclient.NewTrillianClient(ctx, api.logClient, tid) // FIXME:tessera
	resp := tc.GetLatest(0)                                         // FIXME:tessera
	if resp.Status != codes.OK {
		return nil, fmt.Errorf("resp code is %d", resp.Status)
	}
	result := resp.GetLatestResult

	root := &types.LogRootV1{}
	if err := root.UnmarshalBinary(result.SignedLogRoot.LogRoot); err != nil {
		return nil, err
	}

	hashString := hex.EncodeToString(root.RootHash)
	treeSize := int64(root.TreeSize)

	scBytes, err := util.CreateAndSignCheckpoint(ctx, viper.GetString("rekor_server.hostname"), tid, root.TreeSize, root.RootHash, api.signer)
	if err != nil {
		return nil, err
	}

	m := models.InactiveShardLogInfo{
		RootHash:       &hashString,
		TreeSize:       &treeSize,
		TreeID:         stringPointer(fmt.Sprintf("%d", tid)),
		SignedTreeHead: stringPointer(string(scBytes)),
	}
	return &m, nil
}

// handlers for APIs that may be disabled in a given instance

func GetLogInfoNotImplementedHandler(_ tlog.GetLogInfoParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Get Log Info API not enabled in this Rekor instance",
	}

	return tlog.NewGetLogInfoDefault(http.StatusNotImplemented).WithPayload(err)
}

func GetLogProofNotImplementedHandler(_ tlog.GetLogProofParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Get Log Proof API not enabled in this Rekor instance",
	}

	return tlog.NewGetLogProofDefault(http.StatusNotImplemented).WithPayload(err)
}
