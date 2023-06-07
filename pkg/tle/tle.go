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

package tle

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/go-openapi/runtime"
	rekor_pb_common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"google.golang.org/protobuf/encoding/protojson"
)

// GenerateTransparencyLogEntry returns a sigstore/protobuf-specs compliant message containing a
// TransparencyLogEntry as defined at https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_rekor.proto
func GenerateTransparencyLogEntry(anon models.LogEntryAnon) (*rekor_pb.TransparencyLogEntry, error) {
	logIDHash, err := hex.DecodeString(*anon.LogID)
	if err != nil {
		return nil, fmt.Errorf("decoding logID string: %w", err)
	}

	rootHash, err := hex.DecodeString(*anon.Verification.InclusionProof.RootHash)
	if err != nil {
		return nil, fmt.Errorf("decoding inclusion proof root hash: %w", err)
	}

	inclusionProofHashes := make([][]byte, len(anon.Verification.InclusionProof.Hashes))
	for i, hash := range anon.Verification.InclusionProof.Hashes {
		hashBytes, err := hex.DecodeString(hash)
		if err != nil {
			return nil, fmt.Errorf("decoding inclusion proof hash: %w", err)
		}
		inclusionProofHashes[i] = hashBytes
	}

	b, err := base64.StdEncoding.DecodeString(anon.Body.(string))
	if err != nil {
		return nil, fmt.Errorf("base64 decoding body: %w", err)
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}
	eimpl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}

	return &rekor_pb.TransparencyLogEntry{
		LogIndex: *anon.LogIndex,
		LogId: &rekor_pb_common.LogId{
			KeyId: logIDHash,
		},
		KindVersion: &rekor_pb.KindVersion{
			Kind:    pe.Kind(),
			Version: eimpl.APIVersion(),
		},
		IntegratedTime: *anon.IntegratedTime,
		InclusionPromise: &rekor_pb.InclusionPromise{
			SignedEntryTimestamp: anon.Verification.SignedEntryTimestamp,
		},
		InclusionProof: &rekor_pb.InclusionProof{
			LogIndex: *anon.LogIndex,
			RootHash: rootHash,
			TreeSize: *anon.Verification.InclusionProof.TreeSize,
			Hashes:   inclusionProofHashes,
			Checkpoint: &rekor_pb.Checkpoint{
				Envelope: *anon.Verification.InclusionProof.Checkpoint,
			},
		},
		CanonicalizedBody: b, // we don't call eimpl.Canonicalize in the case that the logic is different in this caller vs when it was persisted in the log
	}, nil
}

// MarshalTLEToJSON marshals a TransparencyLogEntry message to JSON according to the protobuf JSON encoding rules
func MarshalTLEToJSON(tle *rekor_pb.TransparencyLogEntry) ([]byte, error) {
	return protojson.Marshal(tle)
}