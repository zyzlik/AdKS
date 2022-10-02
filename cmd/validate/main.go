package main

import (
	"errors"
	"io/ioutil"
	"os"
	"strings"

	manager "github.com/zyzlik/AdKS"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	EnvSecretSpec      = `SLM_SECRET_SPEC_FILE`
	MaxSpecLengthBytes = 10000000 // 10 MB - that is a lot of yaml
)

func main() {
	log.SetFormatter(&log.JSONFormatter{})
	log.Info("Validating Manifest")
	// Read configuration

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

	// 1. Check names for duplicates
	// 2. Check to see if name will be too long for timestamp annotation. Last applied at annotation reserves 20 characters in SLM
	//     K8s allows a maximum of 63 characters in an annotation leaving us 43 characters available for secret name.
	// 3. Check intake source for duplicates
	nameMap := make(map[string]bool)
	intakeMap := make(map[string]bool)
	var valErrors []error

	for _, secret := range allSpecs.Secrets {
		// Check if secret name exists and add to map
		_, exists := nameMap[secret.Name]
		if exists {
			err := errors.New("Duplicate Secret Name: " + secret.Name)
			valErrors = append(valErrors, err)
		}
		nameMap[secret.Name] = true

		if len(secret.Name) > 43 {
			if err := secret.Validate(); err != nil {
				valErrors = append(valErrors, err)
			}
		}

		for _, stage := range secret.Pipeline {
			if err := stage.Validate(); err != nil {
				valErrors = append(valErrors, err)
			}
			_, exists := intakeMap[stage.IntakeSource.Name]
			if exists {
				err := errors.New("Duplicate Intake Source: " + stage.IntakeSource.Name)
				valErrors = append(valErrors, err)
			}
			intakeMap[stage.IntakeSource.Name] = true
		}

	}
	if len(valErrors) > 0 {
		for _, err := range valErrors {
			log.Error(err)
		}
		os.Exit(4)
	}
}
