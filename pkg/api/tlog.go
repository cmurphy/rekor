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

	"github.com/go-openapi/runtime/middleware"
	"github.com/google/trillian/types"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/tlog"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"github.com/sigstore/rekor/pkg/util"
)

// GetLogInfoHandler returns the current size of the tree and the STH
func GetLogInfoHandler(params tlog.GetLogInfoParams) middleware.Responder {
	tc := trillianclient.NewTrillianClient(params.HTTPRequest.Context(), api.logClient, api.treeID)

	// for each inactive shard, get the loginfo
	var inactiveShards []*models.InactiveShardLogInfo
	for _, shard := range api.logRanges.GetInactive() {
		// Get details for this inactive shard
		is, err := inactiveShardLogInfo(params.HTTPRequest.Context(), shard.TreeID, api.cachedCheckpoints)
		if err != nil {
			return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("inactive shard error: %w", err), unexpectedInactiveShardError)
		}
		inactiveShards = append(inactiveShards, is)
	}

	resp := tc.GetLatest(0)
	if resp.Status != codes.OK {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.Err), trillianCommunicationError)
	}
	result := resp.GetLatestResult

	root := &types.LogRootV1{}
	if err := root.UnmarshalBinary(result.SignedLogRoot.LogRoot); err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
	}

	hashString := hex.EncodeToString(root.RootHash)
	treeSize := int64(root.TreeSize)

	scBytes, err := util.CreateAndSignCheckpoint(params.HTTPRequest.Context(),
		viper.GetString("rekor_server.hostname"), api.logRanges.GetActive().TreeID, root.TreeSize, root.RootHash, api.logRanges.GetActive().Signer)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, sthGenerateError)
	}

	logInfo := models.LogInfo{
		RootHash:       &hashString,
		TreeSize:       &treeSize,
		SignedTreeHead: stringPointer(string(scBytes)),
		TreeID:         stringPointer(fmt.Sprintf("%d", api.treeID)),
		InactiveShards: inactiveShards,
	}

	return tlog.NewGetLogInfoOK().WithPayload(&logInfo)
}

func stringPointer(s string) *string {
	return &s
}

func inactiveShardLogInfo(ctx context.Context, tid int64, cachedCheckpoints map[int64]string) (*models.InactiveShardLogInfo, error) {
	tc := trillianclient.NewTrillianClient(ctx, api.logClient, tid)
	resp := tc.GetLatest(0)
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

	m := models.InactiveShardLogInfo{
		RootHash:       &hashString,
		TreeSize:       &treeSize,
		TreeID:         stringPointer(fmt.Sprintf("%d", tid)),
		SignedTreeHead: stringPointer(cachedCheckpoints[tid]),
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
