/*
Copyright 2026 The cert-manager Authors.

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

package route53

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/logging"
	"github.com/aws/smithy-go/middleware"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

type sessionProvider struct {
	AccessKeyID      string
	SecretAccessKey  string
	Ambient          bool
	Region           string
	Role             string
	WebIdentityToken string
	StsProvider      func(aws.Config) StsClient
	userAgent        string
}

type StsClient interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

func (d *sessionProvider) GetSession(ctx context.Context) (aws.Config, error) {
	switch {
	case d.Role == "" && d.WebIdentityToken != "":
		return aws.Config{}, fmt.Errorf("unable to construct route53 provider: role must be set when web identity token is set")
	case d.AccessKeyID == "" && d.SecretAccessKey == "":
		if !d.Ambient && d.WebIdentityToken == "" {
			return aws.Config{}, fmt.Errorf("unable to construct route53 provider: empty credentials; perhaps you meant to enable ambient credentials?")
		}
	case d.AccessKeyID == "" || d.SecretAccessKey == "":
		// It's always an error to set one of those but not the other
		return aws.Config{}, fmt.Errorf("unable to construct route53 provider: only one of access and secret key was provided")
	}

	useAmbientCredentials := d.Ambient && (d.AccessKeyID == "" && d.SecretAccessKey == "") && d.WebIdentityToken == ""

	log := logf.FromContext(ctx)
	optFns := []func(*config.LoadOptions) error{
		// Print AWS API requests but only at cert-manager debug level
		config.WithLogger(logging.LoggerFunc(func(classification logging.Classification, format string, v ...any) {
			log := log.WithValues("aws-classification", classification)
			if classification == logging.Debug {
				log = log.V(logf.DebugLevel)
			}
			log.Info(fmt.Sprintf(format, v...))
		})),
		config.WithClientLogMode(aws.LogDeprecatedUsage | aws.LogRequest),
		config.WithLogConfigurationWarnings(true),
		// Append cert-manager user-agent string to all AWS API requests
		config.WithAPIOptions(
			[]func(*middleware.Stack) error{
				func(stack *middleware.Stack) error {
					return awsmiddleware.AddUserAgentKeyValue("cert-manager", d.userAgent)(stack)
				},
			},
		),
	}

	var envRegionFound bool
	{
		envConfig, err := config.NewEnvConfig()
		if err != nil {
			return aws.Config{}, err
		}
		envRegionFound = envConfig.Region != ""
	}

	if !envRegionFound && d.Region == "" {
		log.Info(
			"Region not found",
			"reason", "The AWS_REGION or AWS_DEFAULT_REGION environment variables were not set and the Issuer region field was empty",
		)
	}

	if d.Region != "" {
		if envRegionFound && useAmbientCredentials {
			log.Info(
				"Ignoring Issuer region",
				"reason", "Issuer is configured to use ambient credentials and AWS_REGION or AWS_DEFAULT_REGION environment variables were found",
				"suggestion", "Since cert-manager 1.16, the Issuer region field is optional and can be removed from your Issuer or ClusterIssuer",
				"issuer-region", d.Region,
			)
		} else {
			optFns = append(optFns,
				config.WithRegion(d.Region),
			)
		}
	}

	switch {
	case d.Role != "" && d.WebIdentityToken != "":
		log.V(logf.DebugLevel).Info("using assume role with web identity")
	case useAmbientCredentials:
		log.V(logf.DebugLevel).Info("using ambient credentials")
		// Leaving credentials unset results in a default credential chain being
		// used; this chain is a reasonable default for getting ambient creds.
		// https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
	default:
		log.V(logf.DebugLevel).Info("not using ambient credentials")
		optFns = append(optFns, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(d.AccessKeyID, d.SecretAccessKey, "")))
	}

	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("unable to create aws config: %w", err)
	}

	if d.Role != "" && d.WebIdentityToken == "" {
		log.V(logf.DebugLevel).WithValues("role", d.Role).Info("assuming role")
		stsSvc := d.StsProvider(cfg)
		result, err := stsSvc.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String(d.Role),
			RoleSessionName: aws.String("cert-manager"),
		})
		if err != nil {
			return aws.Config{}, fmt.Errorf("unable to assume role: %w", err)
		}

		cfg.Credentials = credentials.NewStaticCredentialsProvider(
			*result.Credentials.AccessKeyId,
			*result.Credentials.SecretAccessKey,
			*result.Credentials.SessionToken,
		)
	}

	if d.Role != "" && d.WebIdentityToken != "" {
		log.V(logf.DebugLevel).WithValues("role", d.Role).Info("assuming role with web identity")

		stsSvc := d.StsProvider(cfg)
		result, err := stsSvc.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
			RoleArn:          aws.String(d.Role),
			RoleSessionName:  aws.String("cert-manager"),
			WebIdentityToken: aws.String(d.WebIdentityToken),
		})
		if err != nil {
			return aws.Config{}, fmt.Errorf("unable to assume role with web identity: %w", err)
		}

		cfg.Credentials = credentials.NewStaticCredentialsProvider(
			*result.Credentials.AccessKeyId,
			*result.Credentials.SecretAccessKey,
			*result.Credentials.SessionToken,
		)
	}

	// Log some key values of the loaded configuration, so that users can
	// self-diagnose problems in the field. If users shared logs in their bug
	// reports, we can know whether the region was detected and whether an
	// alternative defaults mode has been configured.
	//
	// TODO(wallrj): Loop through the cfg.ConfigSources and log which config
	// source was used to load the region and credentials, so that it is clearer
	// to the user where environment variables or config files or IMDS metadata
	// are being used.
	log.V(logf.DebugLevel).Info(
		"loaded-config",
		"defaults-mode", cfg.DefaultsMode,
		"region", cfg.Region,
		"runtime-environment", cfg.RuntimeEnvironment,
	)

	return cfg, nil
}

func newSessionProvider(accessKeyID, secretAccessKey, region, role string, webIdentityToken string, ambient bool, userAgent string) *sessionProvider {
	return &sessionProvider{
		AccessKeyID:      accessKeyID,
		SecretAccessKey:  secretAccessKey,
		Ambient:          ambient,
		Region:           region,
		Role:             role,
		WebIdentityToken: webIdentityToken,
		StsProvider:      defaultSTSProvider,
		userAgent:        userAgent,
	}
}

func defaultSTSProvider(cfg aws.Config) StsClient {
	return sts.NewFromConfig(cfg)
}
