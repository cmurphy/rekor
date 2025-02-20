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
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/middleware"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/sigstore/rekor/pkg/api"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"sigs.k8s.io/release-utils/version"
)

var (
	cfgFile     string
	logType     string
	enablePprof bool
	// these map to the operationId as defined in openapi.yaml file
	operationIDs = []string{
		"getLogInfo",
		"createLogEntry",
	}
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "rekor-server",
	Short: "Rekor signature transparency log server",
	Long: `Rekor fulfills the signature transparency role of sigstore's software
	signing infrastructure. It can also be run on its own and is designed to be
	extensible to work with different manifest schemas and PKI tooling`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Logger.Error(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.rekor-server.yaml)")
	rootCmd.PersistentFlags().StringVar(&logType, "log_type", "dev", "logger type to use (dev/prod)")
	rootCmd.PersistentFlags().BoolVar(&enablePprof, "enable_pprof", false, "enable pprof for profiling on port 6060")

	rootCmd.PersistentFlags().Bool("gcp_cloud_profiling.enabled", false, "enable GCP Cloud Profiling")
	rootCmd.PersistentFlags().String("gcp_cloud_profiling.service", "rekor-server", "a name for the service being profiled")
	rootCmd.PersistentFlags().String("gcp_cloud_profiling.service_version", version.GetVersionInfo().GitVersion, "the version of the service being profiled")
	rootCmd.PersistentFlags().String("gcp_cloud_profiling.project_id", "", "GCP project ID")
	rootCmd.PersistentFlags().Bool("gcp_cloud_profiling.enable_oc_telemetry", false, "enable Profiler spans in Cloud Tracing & Cloud Monitoring")

	rootCmd.PersistentFlags().String("trillian_log_server.address", "127.0.0.1", "Trillian log server address")
	rootCmd.PersistentFlags().Uint16("trillian_log_server.port", 8090, "Trillian log server port")
	rootCmd.PersistentFlags().Uint("trillian_log_server.tlog_id", 0, "Trillian tree id")
	rootCmd.PersistentFlags().String("trillian_log_server.sharding_config", "", "path to config file for inactive shards, in JSON or YAML")

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	rootCmd.PersistentFlags().String("rekor_server.hostname", hostname, "public hostname of instance")
	rootCmd.PersistentFlags().String("rekor_server.address", "127.0.0.1", "Address to bind to")

	rootCmd.PersistentFlags().String("rekor_server.signer", "memory",
		`Rekor signer to use. Valid options are: [awskms://keyname, azurekms://keyname, gcpkms://keyname, hashivault://keyname, memory, tink, <filename containing PEM-encoded private key>].
Memory and file-based signers should only be used for testing.`)
	rootCmd.PersistentFlags().String("rekor_server.signer-passwd", "", "Password to decrypt signer private key")
	rootCmd.PersistentFlags().String("rekor_server.tink_kek_uri", "", "Key encryption key for decrypting Tink keyset. Valid options are [aws-kms://keyname, gcp-kms://keyname]")
	rootCmd.PersistentFlags().String("rekor_server.tink_keyset_path", "", "Path to encrypted Tink keyset, containing private key to sign log checkpoints")

	rootCmd.PersistentFlags().String("rekor_server.new_entry_publisher", "", "URL for pub/sub queue to send messages to when new entries are added to the log. Ignored if not set. Supported providers: [gcppubsub]")
	rootCmd.PersistentFlags().Bool("rekor_server.publish_events_protobuf", false, "Whether to publish events in Protobuf wire format. Applies to all enabled event types.")
	rootCmd.PersistentFlags().Bool("rekor_server.publish_events_json", false, "Whether to publish events in CloudEvents JSON format. Applies to all enabled event types.")

	rootCmd.PersistentFlags().Uint16("port", 3000, "Port to bind to")

	rootCmd.PersistentFlags().String("trillian_log_server.tls_ca_cert", "", "Certificate file to use for secure connections with Trillian server")
	rootCmd.PersistentFlags().Bool("trillian_log_server.tls", false, "Use TLS when connecting to Trillian Server")

	rootCmd.PersistentFlags().StringSlice("enabled_api_endpoints", operationIDs, "list of API endpoints to enable using operationId from openapi.yaml")

	rootCmd.PersistentFlags().Uint64("max_request_body_size", 0, "maximum size for HTTP request body, in bytes; set to 0 for unlimited")
	rootCmd.PersistentFlags().Uint64("max_jar_metadata_size", 1048576, "maximum permitted size for jar META-INF/ files, in bytes; set to 0 for unlimited")
	rootCmd.PersistentFlags().Uint64("max_apk_metadata_size", 1048576, "maximum permitted size for apk .SIGN and .PKGINFO files, in bytes; set to 0 for unlimited")

	rootCmd.PersistentFlags().String("http-request-id-header-name", middleware.RequestIDHeader, "name of HTTP Request Header to use as request correlation ID")
	rootCmd.PersistentFlags().String("trace-string-prefix", "", "if set, this will be used to prefix the 'trace' field when outputting structured logs")

	keyAlgorithmTypes := []string{}
	for _, keyAlgorithm := range api.AllowedClientSigningAlgorithms {
		keyFlag, err := signature.FormatSignatureAlgorithmFlag(keyAlgorithm)
		if err != nil {
			panic(err)
		}
		keyAlgorithmTypes = append(keyAlgorithmTypes, keyFlag)
	}
	sort.Strings(keyAlgorithmTypes)
	keyAlgorithmHelp := fmt.Sprintf("signing algorithm to use for signing/hashing (allowed %s)", strings.Join(keyAlgorithmTypes, ", "))
	rootCmd.PersistentFlags().StringSlice("client-signing-algorithms", keyAlgorithmTypes, keyAlgorithmHelp)

	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		log.Logger.Fatal(err)
	}

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	log.Logger.Debugf("pprof enabled %v", enablePprof)
	// Enable pprof
	if enablePprof {
		go func() {
			mux := http.NewServeMux()

			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/{action}", pprof.Index)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)

			srv := &http.Server{
				Addr:         ":6060",
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 10 * time.Second,
				Handler:      mux,
			}

			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Logger.Fatalf("Error when starting or running http server: %v", err)
			}
		}()
	}

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigName("rekor-server")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Logger.Infof("Using config file: %s", viper.ConfigFileUsed())
	}
}
