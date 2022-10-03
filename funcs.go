package manager

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	log "github.com/sirupsen/logrus"
)

var (
	stdout = os.Stdout
	stderr = os.Stderr
)

// Vault is a client interface for AWS Secrets Manager operations. The documentation
// here is copied from the current version of the AWS GO SDK.
type Vault interface {
	// CreateSecret API operation for AWS Secrets Manager.
	//
	// Creates a new secret. A secret in Secrets Manager consists of both the
	// protected secret data and the important information needed to manage the
	// secret.
	//
	// Secrets Manager stores the encrypted secret data in one of a collection
	// of "versions" associated with the secret. Each version contains a copy of
	// the encrypted secret data. Each version is associated with one or more
	// "staging labels" that identify where the version is in the rotation cycle.
	// The SecretVersionsToStages field of the secret contains the mapping of
	// staging labels to the active versions of the secret. Versions without a
	// staging label are considered deprecated and not included in the list.
	//
	// You provide the secret data to be encrypted by putting text in either the
	// SecretString parameter or binary data in the SecretBinary parameter, but
	// not both. If you include SecretString or SecretBinary then Secrets Manager
	// also creates an initial secret version and automatically attaches the
	// staging label AWSCURRENT to the new version.
	//
	// See https://docs.aws.amazon.com/sdk-for-go/api/service/secretsmanager/#SecretsManager.CreateSecret
	CreateSecret(input *secretsmanager.CreateSecretInput) (*secretsmanager.CreateSecretOutput, error)

	// DescribeSecret API operation for AWS Secrets Manager.
	// Retrieves the details of a secret. It does not include the encrypted
	// fields. Secrets Manager only returns fields populated with a value in
	// the response.
	//
	// See https://docs.aws.amazon.com/sdk-for-go/api/service/secretsmanager/#SecretsManager.DescribeSecret
	DescribeSecret(input *secretsmanager.DescribeSecretInput) (*secretsmanager.DescribeSecretOutput, error)

	// GetSecretValue API operation for AWS Secrets Manager.
	//
	// Retrieves the contents of the encrypted fields SecretString or
	// SecretBinary from the specified version of a secret, whichever contains
	// content.
	//
	// See https://docs.aws.amazon.com/sdk-for-go/api/service/secretsmanager/#SecretsManager.GetSecretValue
	GetSecretValue(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error)

	// PutSecretValue API operation for AWS Secrets Manager.
	//
	// Stores a new encrypted secret value in the specified secret. To do this,
	// the operation creates a new version and attaches it to the secret. The
	// version can contain a new SecretString value or a new SecretBinary value.
	// You can also specify the staging labels that are initially attached to
	// the new version.
	//
	// See https://docs.aws.amazon.com/sdk-for-go/api/service/secretsmanager/#SecretsManager.PutSecretValue
	PutSecretValue(input *secretsmanager.PutSecretValueInput) (*secretsmanager.PutSecretValueOutput, error)

	// UpdateSecret API operation for AWS Secrets Manager.
	// TODO: Fill in API description
	UpdateSecret(input *secretsmanager.UpdateSecretInput) (*secretsmanager.UpdateSecretOutput, error)

	// TagResource API operation for AWS Secrets Manager.
	// TODO: Fill in API description
	TagResource(input *secretsmanager.TagResourceInput) (*secretsmanager.TagResourceOutput, error)
	GetResourcePolicy(input *secretsmanager.GetResourcePolicyInput) (*secretsmanager.GetResourcePolicyOutput, error)
	PutResourcePolicy(input *secretsmanager.PutResourcePolicyInput) (*secretsmanager.PutResourcePolicyOutput, error)
}

func ShouldUpdate(sourceOutput,
	targetOutput *secretsmanager.DescribeSecretOutput,
	currentPolicy *string,
	targetPolicyOutput *secretsmanager.GetResourcePolicyOutput,
	kmsKeyId string, tags []*secretsmanager.Tag,
	targetDoesNotExist bool) bool {

	if targetDoesNotExist {
		// secret is new
		log.Info("New secret, adding to root vault")
		return true
	}

	if targetPolicyOutput == nil {
		log.Info("No Target policy, updating secret")
		return true
	}

	if targetPolicyOutput.ResourcePolicy == nil {
		log.Info("No Target resource policy, updating secret")
		return true
	}

	defaultPolicy := &SecretResourcePolicy{}

	err := json.Unmarshal([]byte(*currentPolicy), defaultPolicy)
	if err != nil {
		log.Error("Error marshaling current policy json in ShouldUpdate " + err.Error())
		return false
	}

	targetResourcePolicy := &SecretResourcePolicy{}
	err = json.Unmarshal([]byte(*targetPolicyOutput.ResourcePolicy), targetResourcePolicy)
	if err != nil {
		log.Error("Error marshaling target policy json in ShouldUpdate: " + err.Error())
		return false
	}

	if !reflect.DeepEqual(defaultPolicy, targetResourcePolicy) {
		log.Info("Resource policy has been modified.")
		return true
	}

	if sourceOutput.ARN != nil && sourceOutput.LastChangedDate.After(*targetOutput.LastChangedDate) {
		// source secret was created, changed more recently than target secret
		log.Info("Source secret last changed date more recent than target")
		return true
	}

	if sourceOutput.ARN != nil && sourceOutput.LastRotatedDate != nil {
		// source secret was rotated more recently than target secret
		if targetOutput.LastRotatedDate == nil {
			log.Info("Target was not rotated, updating")
			return true
		}
		if sourceOutput.LastRotatedDate.After(*targetOutput.LastRotatedDate) {
			log.Info("Source was rotated more recently than target, updating")
			return true
		}
	}

	// If kms key in manifest has changed
	if ShouldUpdateKmsKey(kmsKeyId, *targetOutput.KmsKeyId) {
		return true
	}

	// Sort target output tags
	sortedSourceTags := SortTags(tags)
	targetOutputTags := SortTags(targetOutput.Tags)

	if ShouldUpdateTags(sortedSourceTags, targetOutputTags) {
		return true
	}

	// default to disallow
	return false
}

func DeriveRootVaultSecretName(secretName, stageName string) string {
	// TODO normalize input names
	//
	// xform:
	//	1. remove trailing and leading spaces
	//
	// Consider:
	//	1. Input case sensitivity
	//	2. Output domain: The secret name must be ASCII letters, digits, or the following characters: /_+=.@-
	//	3. Protected characters with special meanings in secretsmanager (for example, /)
	//	4. Collisions created by name normalization..
	//		For example, if this code transforms all special characters into underscore then secrets with
	//		different names will collide in vault storage. We could disambiguate to detect such collisions
	//		using metadata. Or we could put more restrictive constraints on the input domain. (I like this
	//		option).
	normalizedSecretName := strings.TrimSpace(secretName)
	normalizedStageName := strings.TrimSpace(stageName)

	return fmt.Sprintf("root-vault/%s/%s", normalizedSecretName, normalizedStageName)
}

func DoIntake(sess *session.Session,
	kmsKeyId string, source, root Vault,
	secrets []Secret) {
	for _, secret := range secrets {
		err := secret.Intake(source, root, kmsKeyId)
		if err != nil {
			log.Error(err)
		}

	}
}

func ErrorIs(received error, expected string) bool {
	if aerr, ok := received.(awserr.Error); ok {
		return aerr.Code() == expected
	}
	return false
}

func GetSecretFromVault(vault Vault, input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
	result, err := vault.GetSecretValue(input)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func DoDeliver(source Vault, secrets []Secret) error {
	if source == nil {
		return errors.New(`invalid source vault`)
	}

	if len(secrets) <= 0 {
		return errors.New(`invalid secrets list`)
	}

	var errors []error
	for _, secret := range secrets {
		if err := secret.Validate(); err != nil {
			errors = append(errors, err)
			continue
		}
		secretErrs := secret.Deliver(source)
		errors = append(errors, secretErrs...)
	}

	numOfErr := len(errors)
	if numOfErr == 0 {
		return nil
	}
	stdout.WriteString(fmt.Sprintf("------------- There were %d errors -------------\n", numOfErr))
	for _, err := range errors {
		fmt.Println(err)
	}

	return nil
}

func SortTags(tags []*secretsmanager.Tag) []*secretsmanager.Tag {
	result := make([]*secretsmanager.Tag, len(tags))
	copy(result, tags)

	sort.SliceStable(result, func(i, j int) bool {
		return *tags[i].Key < *tags[j].Key
	})
	return result
}

func ShouldUpdateTags(sourceTags []*secretsmanager.Tag, targetTags []*secretsmanager.Tag) bool {
	if len(sourceTags) != len(targetTags) {
		log.Info("Tag length mismatch, updating")
		return true
	}
	// Check pre-sorted tags for differences
	for i, tag := range sourceTags {
		if *tag.Key != *targetTags[i].Key || *tag.Value != *targetTags[i].Value {
			log.Info("Tag " + *tag.Key + " was updated with value: " + *tag.Value + ". Updating...")
			return true
		}
	}
	return false
}

func ShouldUpdateKmsKey(originalKmsKey, newKmsKey string) bool {
	if originalKmsKey != newKmsKey {
		log.Info("New KMS key detected, updating")
		return true
	}
	return false
}
