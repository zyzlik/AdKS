package main

import (
	"os"

	manager "github.com/zyzlik/AdKS"
	log "github.com/sirupsen/logrus"
)

const (
	EnvSecretSpec      = `SLM_SECRET_SPEC_FILE`
	BaseSecretSpec     = `SLM_BASE_SECRET_FILE`
	MaxSpecLengthBytes = 10000000 // 10 MB - that is a lot of yaml
)

func main() {

	log.SetFormatter(&log.JSONFormatter{})
	log.Info("starting diff")
	// call secondary package
	specFiles, ok := os.LookupEnv(EnvSecretSpec)
	if !ok {
		log.Error("secret spec not provided")
		os.Exit(1)
	}

	baseFiles, ok := os.LookupEnv(BaseSecretSpec)
	if !ok {
		log.Error("secret spec not provided")
		os.Exit(1)
	}
	err := manager.RunDiff(specFiles, baseFiles)
	if err != nil {
		log.Error("Errors detected with new k8s targets cluster or namespace")
		os.Exit(1)

	}

}