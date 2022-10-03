package manager

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreV1 "k8s.io/api/core/v1"
)

const (
	MaxSpecLengthBytes = 10000000 // 10 MB - that is a lot of yaml

)

var (
	validateKubeTargets = validatek8sTargets
)
var t fakeT

type fakeT struct{}

func (t fakeT) Errorf(format string, args ...interface{}) { fmt.Printf(format+"\n", args...) }

func RunDiff(newSecretsFiles string, baseSecretFiles string) error {
	newSpecs := readSecretSpec(newSecretsFiles)
	baseSpecs := SecretList{}
	diffSecrets := SecretList{}

	if baseSecretFiles != "" {
		baseSpecs = readSecretSpec(baseSecretFiles)
	} else {
		log.Info("Base Secret spec is emtpy, checking targets for single new file.")
		err := validateKubeTargets(newSpecs)
		if err != nil {
			return err
		}
		return nil
	}
	//compare these
	if diff := cmp.Diff(baseSpecs, newSpecs); diff != "" {
		t.Errorf("secret.yml changes (-base +new):\n%s", diff)
		// put old secrets into a map
		// check new secrets for exists, has changes
		// if no entry also check
		baseMap := make(map[string]Secret)
		for _, secret := range baseSpecs.Secrets {
			baseMap[secret.Name] = secret
		}

		for _, secret := range newSpecs.Secrets {
			if baseSecretValue, exists := baseMap[secret.Name]; exists {
				//Secret is not new, see if it changed
				if cmp.Equal(baseSecretValue, secret) != true {
					diffSecrets.Secrets = append(diffSecrets.Secrets, secret)
				}
			} else {
				//secret is new
				diffSecrets.Secrets = append(diffSecrets.Secrets, secret)
			}
		}
		err := validateKubeTargets(diffSecrets)
		if err != nil {
			return err
		}
	}
	return nil
}

func validatek8sTargets(secretList SecretList) error {
	for _, secret := range secretList.Secrets {
		for _, stage := range secret.Pipeline {
			err := checkTargets(stage)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func checkTargets(pipeline Stage) error {
	isError := false
	for _, target := range pipeline.Targets {
		if !target.Kubernetes.IsEmpty() {
			// check namespace and connection.
			aws_session_token := os.Getenv("AWS_SESSION_TOKEN")
			if target.Kubernetes.AccountRole == "" {
				os.Setenv("AWS_SESSION_TOKEN", "")
			}

			kubernetesClient, err := getKubernetesClient(target.Kubernetes.Cluster, target.Kubernetes.AccountRole)
			if err != nil {
				log.Error("Error accessing cluster: " + target.Kubernetes.Cluster + " k8s error message: " + err.Error())
				isError = true
				continue // break here and try next target
			}
			for _, namespace := range target.Kubernetes.Namespace {
				log.Info("Checking for namespace: " + namespace + " in cluster: " + target.Kubernetes.Cluster)
				kubeClient := kubernetesClient.CoreV1().Namespaces()
				_, err := kubeClient.Get(context.Background(), namespace, metaV1.GetOptions{})
				//result, err := secretsClient.List(context.Background(), metaV1.ListOptions{})
				if err != nil {
					log.Warn("Error accessing namespace: " + namespace + " in cluster: " + target.Kubernetes.Cluster + ". Attemping to create...")
					nsName := &coreV1.Namespace{
						ObjectMeta: metaV1.ObjectMeta{
							Name: namespace,
						},
					}

					kubeClient.Create(context.Background(), nsName, metaV1.CreateOptions{})

					_, err_retry := kubeClient.Get(context.Background(), namespace, metaV1.GetOptions{})
					if err_retry != nil {
						log.Error("Error creating namespace: " + namespace + " in cluster: " + target.Kubernetes.Cluster + " k8s error message: " + err.Error())
						isError = true
					}
				}
			}
			//Restore session token here before doing anything else
			os.Setenv("AWS_SESSION_TOKEN", aws_session_token)
		}
	}
	if isError {
		return errors.New("Error communicating with kubernetes cluster or namespace, check workflow logs for specific cluster/ns combinations")
	}
	return nil
}

func readSecretSpec(specFiles string) SecretList {

	allSpecs := SecretList{}
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
		tmpSpec := SecretList{}
		err = yaml.Unmarshal(config, &tmpSpec)
		if err != nil {
			log.Error(err.Error())
			os.Exit(3)
		}
		allSpecs.Secrets = append(allSpecs.Secrets, tmpSpec.Secrets...)
	}
	return allSpecs
}