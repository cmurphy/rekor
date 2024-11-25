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

package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/go-openapi/runtime"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/tle"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/verify"
)

type getCmdOutput struct {
	Body     interface{}
	LogIndex int
	UUID     string
	LogID    string
}

func (g *getCmdOutput) String() string {
	s := fmt.Sprintf("LogID: %v\n", g.LogID)

	s += fmt.Sprintf("Index: %d\n", g.LogIndex)
	s += fmt.Sprintf("UUID: %s\n", g.UUID)
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetIndent("", "  ")
	_ = e.Encode(g.Body)
	s += fmt.Sprintf("Body: %s\n", b.Bytes())
	return s
}

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Rekor get command",
	Long:  `Get information regarding entries in the transparency log`,
	PreRun: func(cmd *cobra.Command, _ []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.CliLogger.Fatalf("Error initializing cmd line args: %w", err)
		}
	},
	Run: format.WrapCmd(func(_ []string) (interface{}, error) {
		ctx := context.Background()
		rekorClient, err := client.GetRekorClient(viper.GetString("rekor_server"), client.WithUserAgent(UserAgent()), client.WithRetryCount(viper.GetUint("retry")), client.WithLogger(log.CliLogger))
		if err != nil {
			return nil, err
		}

		logIndex := viper.GetString("log-index")
		uuid := viper.GetString("uuid")
		if logIndex == "" && uuid == "" {
			return nil, errors.New("either --uuid or --log-index must be specified")
		}
		// retrieve rekor pubkey for verification
		verifier, err := loadVerifier(rekorClient)
		if err != nil {
			return nil, fmt.Errorf("retrieving rekor public key")
		}

		if logIndex != "" {
			params := entries.NewGetLogEntryByIndexParams()
			params.SetTimeout(viper.GetDuration("timeout"))
			logIndexInt, err := strconv.ParseInt(logIndex, 10, 0)
			if err != nil {
				return nil, fmt.Errorf("error parsing --log-index: %w", err)
			}
			params.LogIndex = logIndexInt

			resp, err := rekorClient.Entries.GetLogEntryByIndex(params)
			if err != nil {
				return nil, err
			}
			var e models.LogEntryAnon
			for ix, entry := range resp.Payload {
				// verify log entry
				e = entry
				if err := verify.VerifyLogEntry(ctx, &e, verifier); err != nil {
					return nil, fmt.Errorf("unable to verify entry was added to log: %w", err)
				}

				// verify checkpoint
				if entry.Verification.InclusionProof.Checkpoint != nil {
					if err := verify.VerifyCheckpointSignature(&e, verifier); err != nil {
						return nil, err
					}
				}

				return parseEntry(ix, entry)
			}
		}

		return nil, errors.New("entry not found")
	}),
}

func parseEntry(uuid string, e models.LogEntryAnon) (interface{}, error) {
	if viper.GetString("format") == "tle" {
		return tle.GenerateTransparencyLogEntry(e)
	}

	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}
	eimpl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}

	obj := getCmdOutput{
		Body:     eimpl,
		UUID:     uuid,
		LogIndex: int(*e.LogIndex),
		LogID:    *e.LogID,
	}

	return &obj, nil
}

func init() {
	initializePFlagMap()
	if err := addUUIDPFlags(getCmd, false); err != nil {
		log.CliLogger.Fatal("Error parsing cmd line args: ", err)
	}
	if err := addLogIndexFlag(getCmd, false); err != nil {
		log.CliLogger.Fatal("Error parsing cmd line args: ", err)
	}

	rootCmd.AddCommand(getCmd)
}
