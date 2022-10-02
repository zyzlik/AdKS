package main

import (
	"io/ioutil"
	"os"
	"strings"

	manager "github.com/zyzlik/AdKS"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	EnvSecretSpec = `SLM_SECRET_SPEC_FILE`
	EnvReaderRole = `SLM_VAULT_READER_ROLE_ARN`

	DefaultReaderRoleARN = `SLM_VAULT_READER_ROLE_ARN`
	EnvKubeConfigPath    = `KUBECONFIG`

	MaxSpecLengthBytes = 10000000 // 10 MB - that is a lot of yaml
)

var (
	stdout = os.Stdout
	stderr = os.Stderr
)

func main() {

	log.SetFormatter(&log.JSONFormatter{})
	log.Info("starting deliver")

	// Role the SLM uses to read from the root vault
	readerRole, ok := os.LookupEnv(EnvReaderRole)
	if !ok {
		readerRole = DefaultReaderRoleARN
	}

	specFiles, ok := os.LookupEnv(EnvSecretSpec)
	if !ok {
		log.Error("secret spec not provided")
		os.Exit(1)
	}

	// The secret spec file should be a dictionary at the top level with a single
	// key: secrets (as described by the SecretList type). The associated value
	// is a list of Secrets.
	allSpecs := manager.SecretList{}
	for _, specFile := range strings.Split(specFiles, ",") {

		fi, err := os.Stat(specFile)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
		if fi.Size() > MaxSpecLengthBytes {
			log.Error("spec file too large")
			os.Exit(1)
		}
		// Read configuration
		config, err := ioutil.ReadFile(specFile)
		if err != nil {
			log.Error(err.Error())
			os.Exit(2)
		}
		tmpSpec := manager.SecretList{}
		err = yaml.Unmarshal(config, &tmpSpec)
		if err != nil {
			log.Error(err.Error())
			os.Exit(3)
		}
		allSpecs.Secrets = append(allSpecs.Secrets, tmpSpec.Secrets...)
	}

	// Initial credentials loaded from SDK's default credential chain. Such as
	// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
	// Role. These credentials will be used to to make the STS Assume Role API.
	sess := session.Must(session.NewSession())
	// Assume the root vault reader role
	vaultCreds := stscreds.NewCredentials(sess, readerRole)
	// Handle on the root vault
	vault := secretsmanager.New(sess, &aws.Config{
		Credentials: vaultCreds,
		Region:      aws.String("us-east-1"),
	})

	manager.DoDeliver(vault, allSpecs.Secrets)
}