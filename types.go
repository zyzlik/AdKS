package manager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	typedV1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

const principal_role string = "arn:aws:iam::047313371957:role/production-ue1-devops-admin"

type SecretList struct {
	Secrets []Secret `yaml:"secrets"`
}

// Shape is a string enumeration that tells the secret
// lifecycle manager how to handle the material. For
// example, secretsmanager secrets might be created as
// string or blob data. A binary secret or structured
// file content should be created using a secretsmanager
// blob type, where a simple password should use string.
//
// We need to determine what shapes we might handle beyond
// simple opaque handling.
type Shape string

func (s Shape) IsBinary() bool {
	if !s.Validate() {
		return false
	}
	if s == "binary" {
		return true
	}
	return false
}

func (s Shape) IsPlaintext() bool {
	if !s.Validate() {
		return false
	}
	if s == "plaintext" {
		return true
	}
	return false
}

func (s Shape) IsKeyValue() bool {
	if !s.Validate() {
		return false
	}
	if s == "key-value" {
		return true
	}
	return false
}

func (s Shape) Validate() bool {
	if s != "binary" && s != "plaintext" && s != "key-value" {
		return false
	}
	return true
}

type SecretResourceCondition struct {
	StringNotLike map[string][]string
}

// Secret represents a variable in the system where the value:
//  - must be kept confidential at rest and in transit
//  - must have a consistent value within a stage
type Secret struct {
	Name     string         `yaml:"name" validate:"required"`
	Metadata SecretMetadata `yaml:"metadata" validate:"required"`
	Shape    Shape          `yaml:"shape" validate:""`
	// there are some secrets that must be the same across all
	// environments, e.g. DataDog API keys, etc. A global
	// secret will only store and socialize a single secret
	// across all stages in the pipeline. For that reason,
	// there is no functional difference between a single stage
	// pipeline with several targets and a multi-stage pipline
	// with the same targets for global secrets.
	Tags     map[string]string `yaml:"tags"`
	Global   bool              `yaml:"global"`
	Pipeline []Stage           `yaml:"pipeline,omitempty" validate:"unique"`
}

func (secret *Secret) Intake(source, root Vault, kmsKeyId string) error {
	if source == nil {
		return errors.New(`missing source vault`)
	}

	if root == nil {
		return errors.New(`missing root vault`)
	}

	var errors []error
	for _, stage := range secret.Pipeline {
		intakeErr := stage.Intake(secret, source, root, kmsKeyId)
		if intakeErr != nil {
			errors = append(errors, intakeErr)
		}
	}

	numOfErr := len(errors)
	if numOfErr == 0 {
		return nil
	}
	stdout.WriteString(fmt.Sprintf("------------- There were %d intake errors -------------\n", numOfErr))
	for _, err := range errors {
		log.Error(err)
	}
	return nil
}

func (secret *Secret) Validate() error {
	if len(secret.Name) <= 0 {
		return errors.New(`missing secret name`)
	}
	if len(secret.Name) > 43 {
		return errors.New(`secret name greater than 43 characters`)
	}
	if err := secret.Metadata.Validate(); err != nil {
		return err
	}
	if len(secret.Pipeline) <= 0 {
		return errors.New(`missing pipeline`)
	}

	return nil
}

func (secret *Secret) Deliver(
	source Vault) []error {
	log.Info("Delivering secret: " + secret.Name)
	var errors []error
	for _, stage := range secret.Pipeline {
		// Abort delivery into subsequent stages if delivery to a stage fails.
		log.Info("Starting pipeline stage: " + stage.Name)
		if err := stage.Validate(); err != nil {
			errors = append(errors, err)
			continue
		}
		if stageErrs := stage.Deliver(source, secret); stageErrs != nil {
			errors = append(errors, stageErrs...)
		}
	}
	return errors
}

// SecretMetadata contains information that humans use to understand the secret,
// how the secret is used, who is responsible for that secret, and its history.
type SecretMetadata struct {
	TeamOwner      string    `yaml:"team_owner" validate:"required,alpha"`
	UseDescription string    `yaml:"use_description" validate:"required,alphanumeric"`
	CreatedAt      time.Time `yaml:"created_at" validate:"required"`
}

func (metadata *SecretMetadata) Validate() error {
	if len(metadata.TeamOwner) <= 0 {
		return errors.New(`missing team owner`)
	}

	if len(metadata.UseDescription) <= 0 {
		return errors.New(`Missing description`)
	}
	return nil
}

type SecretResourcePolicyStatement struct {
	Effect    string
	Principal string
	Action    string
	Resource  string
	Condition SecretResourceCondition
}

type SecretResourcePolicy struct {
	Version   string
	Statement []SecretResourcePolicyStatement
}

// Stage describes the set of targets where a common version of the secret must be
// delivered, and where the initial value should be sourced from (intake).
//
// Until the lifecycle manager can generate secrets or coordinate rotation, or where
// secret material cannot be generated, it will be provided to the lifecycle manager
// via intake. During intake the manager copies the material into the root vault.
// The manager delivers the material from the root vault into each target for the
// stage during lifecycle actions.
type Stage struct {
	// Name is a symbolic name for the deployment stage. Humans use this name
	// to reason about its place in the pipeline, the impact of compromise,
	// and volatility. It is also used by internal processes to derive
	// internal identifiers.
	Name string `yaml:"name" validate:"required,alphanumeric"`

	// Production identifies stages that should be treated as production. Operators
	// should assume that a production version of a secret is used to protect
	// sensitive data and priviliged access to other production systems.
	Production bool `yaml:"production,omitempty"`

	// Targets is a list of delivery targets for this stage.
	Targets []Target `yaml:"targets,omitempty"`

	// IntakeSource specifies an AWS Secrets Manager secret where the lifecycle
	// manager can source the secret value for this stage.
	IntakeSource SecretsManagerIntakeSource `yaml:"intake_source,omitempty"`
}

func (stage *Stage) Validate() error {
	if len(stage.Name) <= 0 {
		return errors.New(`Missing stage name`)
	}

	if err := stage.IntakeSource.Validate(); err != nil {
		return errors.New(`Intake source not defined for stage ` + stage.Name + `. ` + err.Error())
	}
	if len(stage.Targets) <= 0 {
		log.Info("No targets specified for " + stage.Name + ". Skipping delivery.")
		return nil
	}
	for _, target := range stage.Targets {
		if err := target.Validate(); err != nil {
			return err
		}
	}

	return nil

}

func (stage *Stage) Intake(secret *Secret, source, root Vault, kmsKeyId string) error {
	sourceSecretName := stage.IntakeSource.Name
	targetSecretName := DeriveRootVaultSecretName(secret.Name, stage.Name)

	// Determine if intake secret is real (DescribeSecret)
	log.Info("Secret name to intake is: " + sourceSecretName)
	sourceSecretOutput, sourceErr := source.DescribeSecret(&secretsmanager.DescribeSecretInput{SecretId: aws.String(sourceSecretName)})
	sourceDoesNotExist := sourceErr != nil && ErrorIs(sourceErr, secretsmanager.ErrCodeResourceNotFoundException)

	// Determine if root vault copy exists (DescribeSecret)
	rootSecretOutput, targetErr := root.DescribeSecret(&secretsmanager.DescribeSecretInput{SecretId: aws.String(targetSecretName)})
	targetDoesNotExist := targetErr != nil && ErrorIs(targetErr, secretsmanager.ErrCodeResourceNotFoundException)

	atags := []*secretsmanager.Tag{}
	atags = append(atags, &secretsmanager.Tag{
		Key:   aws.String("slm.managed-by"),
		Value: aws.String("true"),
	})
	atags = append(atags, &secretsmanager.Tag{
		Key:   aws.String("slm.version"),
		Value: aws.String("v1"),
	})

	for _, k := range secret.Tags {
		atags = append(atags, &secretsmanager.Tag{
			Key:   aws.String(k),
			Value: aws.String(secret.Tags[k])})
	}
	sortedTags := SortTags(atags)
	principals, principalErr := json.Marshal(&[]string{
		principal_role,
	})
	if principalErr != nil {
		return errors.New("Failed to unmarshal principal for " + secret.Name + " " + principalErr.Error())
	}

	getResourcePolicyInput := &secretsmanager.GetResourcePolicyInput{
		SecretId: aws.String(targetSecretName),
	}

	defaultPolicyString := aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"secretsmanager:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotLike\":{\"aws:PrincipalArn\":" + string(principals) + "}}}]}")
	targetResourcePolicyOutput, policyErr := root.GetResourcePolicy(getResourcePolicyInput)
	if policyErr != nil {
		log.Error("Error retrieving policy for root secret " + policyErr.Error())

	}

	if !ShouldUpdate(sourceSecretOutput, rootSecretOutput, defaultPolicyString, targetResourcePolicyOutput, kmsKeyId, sortedTags, targetDoesNotExist) {
		log.Info("No changes to " + sourceSecretName + ". Skipping update.")
		return nil
	}
	// Should update if policy changes. Separate flow for resource policy and other fields.

	if targetDoesNotExist {
		log.Info("Secret " + targetSecretName + " doesn't exist. Creating...")
		if sourceDoesNotExist {

			return newSecretsManagerError(GetSecretValueError, sourceSecretName, targetSecretName, "Failed to find secret in intake vault. "+targetErr.Error())
		}
		inputSecretValue, err := source.GetSecretValue(&secretsmanager.GetSecretValueInput{SecretId: aws.String(sourceSecretName)})
		if err != nil {
			return newSecretsManagerError(GetSecretValueError, sourceSecretName, targetSecretName, "Error getting secret from intake vault. "+err.Error())
		}
		if inputSecretValue.SecretString != nil {
			if _, err := root.CreateSecret(&secretsmanager.CreateSecretInput{
				Name:         aws.String(targetSecretName),
				Description:  aws.String(secret.Metadata.UseDescription),
				KmsKeyId:     aws.String(kmsKeyId),
				SecretString: inputSecretValue.SecretString,
				Tags:         sortedTags,
			}); err != nil {
				return newSecretsManagerError(CreateSecretError, sourceSecretName, targetSecretName, "Error creating secret in root vault. "+err.Error())
			}
		} else if inputSecretValue.SecretBinary != nil {
			if _, err := root.CreateSecret(&secretsmanager.CreateSecretInput{
				Name:         aws.String(targetSecretName),
				Description:  aws.String(secret.Metadata.UseDescription),
				KmsKeyId:     aws.String(kmsKeyId),
				SecretBinary: inputSecretValue.SecretBinary,
				Tags:         sortedTags,
			}); err != nil {
				return newSecretsManagerError(CreateSecretError, sourceSecretName, targetSecretName, "Error creating secret in root vault. "+err.Error())
			}
		}

		log.Info("secret created")

	} else {
		log.Info("Secret " + targetSecretName + " already exists. Updating...")
		// Moving tag resource to the top. We need to refactor this code to be smarter,
		// but for now let's update the tags and resource for every update.

		if _, err := root.TagResource(&secretsmanager.TagResourceInput{
			SecretId: aws.String(targetSecretName),
			Tags:     sortedTags,
		}); err != nil {
			return newSecretsManagerError(CreateSecretError, sourceSecretName, targetSecretName, "Failed to update tags in root vault. "+err.Error())
		}
		newResourcePolicyInput := &secretsmanager.PutResourcePolicyInput{
			ResourcePolicy: defaultPolicyString,
			SecretId:       aws.String(targetSecretName),
		}
		if _, err := root.PutResourcePolicy(newResourcePolicyInput); err != nil {
			return newSecretsManagerError(UpdateSecretTagsError, sourceSecretName, targetSecretName, "Failed to update policy in root vault. "+err.Error())
		}

		var inputSecretValue *secretsmanager.GetSecretValueOutput

		if sourceDoesNotExist {
			log.Info("Failed to find " + sourceSecretName + " in intake vault. Use existing root value.")
			inputSecretValue, targetErr = root.GetSecretValue(&secretsmanager.GetSecretValueInput{SecretId: aws.String(targetSecretName)})
			if targetErr != nil {
				return newSecretsManagerError(GetSecretValueError, sourceSecretName, targetSecretName, "Failed to get existing root vault secret. "+targetErr.Error())
			}
		} else {
			log.Info(sourceSecretName + "was found in intake vault. Use intake value.")
			inputSecretValue, sourceErr = source.GetSecretValue(&secretsmanager.GetSecretValueInput{SecretId: aws.String(sourceSecretName)})
			if sourceErr != nil {
				return newSecretsManagerError(GetSecretValueError, sourceSecretName, targetSecretName, "Failed to get existing intake vault secret. "+sourceErr.Error())
			}
		}

		if inputSecretValue.SecretString != nil {
			if _, err := root.UpdateSecret(&secretsmanager.UpdateSecretInput{
				Description:  aws.String(secret.Metadata.UseDescription),
				KmsKeyId:     aws.String(kmsKeyId),
				SecretId:     aws.String(targetSecretName),
				SecretString: inputSecretValue.SecretString,
			}); err != nil {
				return newSecretsManagerError(UpdateSecretError, sourceSecretName, targetSecretName, "Failed to update secret in root vault. "+err.Error())
			}
		} else if inputSecretValue.SecretBinary != nil {
			if _, err := root.UpdateSecret(&secretsmanager.UpdateSecretInput{
				Description:  aws.String(secret.Metadata.UseDescription),
				KmsKeyId:     aws.String(kmsKeyId),
				SecretId:     aws.String(targetSecretName),
				SecretBinary: inputSecretValue.SecretBinary,
			}); err != nil {
				return newSecretsManagerError(UpdateSecretError, sourceSecretName, targetSecretName, "Failed to update secret in root vault. "+err.Error())
			}
		}

		log.Info("secret updated")

	}

	return nil
}

func (stage *Stage) Deliver(source Vault, secret *Secret) []error {
	var errors []error
	for _, target := range stage.Targets {
		// Continue delivering to targets even if delivery to any individual target fails.
		if err := target.Deliver(source, stage, secret); err != nil {
			errors = append(errors, err...)
		}
	}
	return errors
}

type Target struct {
	Kubernetes KubernetesTarget `yaml:"kubernetes,omitempty" validate:"required_without=SecretsManager"`
}

func (target *Target) Validate() error {
	if !target.Kubernetes.IsEmpty() {
		return target.Kubernetes.Validate()
	}
	// Can add validation for other potential types
	return nil
}

func (target *Target) Deliver(
	source Vault, stage *Stage,
	secret *Secret) []error {
	if !target.Kubernetes.IsEmpty() {
		errs := target.Kubernetes.Deliver(source, stage.Name, secret.Name, secret.Shape)
		if errs != nil {
			return errs
		}
	}
	return nil
}

// KubernetesTarget identifies a unique last-mile vault
// and handle in EKS.
type KubernetesTarget struct {
	// Account location of the cluster and role to assume for interaction with the cluster
	AccountRole AccountRole `yaml:"account_role"`

	// TODO add fields for cluster identification, cluster ID, some tag, endpoint address, etc
	Cluster string `yaml:"cluster" validate:"required"`

	// The Kubernetes namespace where the secret must be delivered
	Namespace []string `yaml:"namespace" validate:"required"`

	// The Kubernetes secret data key for this particular secret. By default it
	DataField string `yaml:"data_field" validate:"required"`

	// The Kubernetes secret object where the secret must be delivered
	Name string `yaml:"name" validate:"required"`
}

func (kubernetesTarget *KubernetesTarget) Validate() error {
	if kubernetesTarget.Name == "" {
		return errors.New(`Kubernetes target secret name missing`)
	}
	if kubernetesTarget.Namespace == nil {
		return errors.New(`Kubernetes target namespace missing`)
	}
	if kubernetesTarget.Cluster == "" {
		return errors.New(`Kubernetes target cluster name missing`)
	}
	return nil

}

func (kubernetesTarget *KubernetesTarget) Deliver(
	source Vault, stageName,
	secretName string, shape Shape) []error {
	if len(stageName) <= 0 {
		return []error{errors.New(`invalid stage name`)}
	}

	if len(secretName) <= 0 {
		return []error{errors.New(`invalid secret name`)}
	}

	if source == nil {
		return []error{errors.New(`invalid source vault`)}
	}

	sourceVaultId := DeriveRootVaultSecretName(secretName, stageName)

	log.Info("Delivering root vault secret " + sourceVaultId + " to kubernetes target " + kubernetesTarget.Name)
	sourceDescribeInput := &secretsmanager.DescribeSecretInput{SecretId: aws.String(sourceVaultId)}
	if err := sourceDescribeInput.Validate(); err != nil {
		log.Error("error with input source secret")
		return []error{newSecretsManagerError(SecretInputValidationError, sourceVaultId, kubernetesTarget.Name, "Validation error with root vault secret. "+err.Error())}
	}
	sourceDescribeOutput, err := source.DescribeSecret(sourceDescribeInput)
	sourceNotFound := err != nil && ErrorIs(err, secretsmanager.ErrCodeResourceNotFoundException)
	if sourceNotFound {
		log.Error("error describing source secret")
		return []error{newSecretsManagerError(GetSecretValueError, sourceVaultId, kubernetesTarget.Name, "Failed to get secret in root vault during kubernetes delivery. "+err.Error())}
	}

	sourceGetValueInput := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(sourceVaultId),
	}
	if err := sourceGetValueInput.Validate(); err != nil {
		log.Error("error validating  secret value input")
		return []error{newSecretsManagerError(SecretInputValidationError, sourceVaultId, kubernetesTarget.Name, "Validation error with root vault secret. "+err.Error())}
	}

	sourceSecret, err := GetSecretFromVault(source, sourceGetValueInput)
	if err != nil {
		log.Error("error getting source secret from vault")
		return []error{newSecretsManagerError(GetSecretValueError, sourceVaultId, kubernetesTarget.Name, "Failed to get secret in root vault during kubernetes delivery. "+err.Error())}
	}

	aws_session_token := os.Getenv("AWS_SESSION_TOKEN")
	if kubernetesTarget.AccountRole == "" {
		os.Setenv("AWS_SESSION_TOKEN", "")
		log.Info("Delivering legacy kops using KUBECONFIG : " + os.Getenv("KUBECONFIG"))
	}

	kubernetesClient, err := getKubernetesClient(kubernetesTarget.Cluster, kubernetesTarget.AccountRole)
	if err != nil {
		return []error{errors.New("Error getting kubernetes client: " + err.Error())}
	}
	var apply_errors []error
	for _, namespace := range kubernetesTarget.Namespace {
		//Do for each namespace
		secretsClient := kubernetesClient.CoreV1().Secrets(namespace)

		// User has an option to overwrite the key in kubernetes secret resource for plaintext secrets
		if kubernetesTarget.DataField != "" && (shape.IsPlaintext() || shape.IsBinary()) {
			secretName = kubernetesTarget.DataField
		}

		_, applyErr := kubernetesTarget.ApplyKubernetesManifest(secretsClient,
			namespace,
			secretName,
			sourceSecret,
			sourceDescribeOutput,
		)
		if applyErr != nil {
			apply_errors = append(apply_errors, applyErr)
		}
	}

	//Restore session token here before doing anything else
	os.Setenv("AWS_SESSION_TOKEN", aws_session_token)
	if len(apply_errors) > 0 {
		return apply_errors
	}
	return nil
}

func (kubernetesTarget *KubernetesTarget) ApplyKubernetesManifest(
	secretsClient typedV1.SecretInterface,
	namespace string,
	secretName string,
	rootSecret *secretsmanager.GetSecretValueOutput,
	rootSecretDescribeOutput *secretsmanager.DescribeSecretOutput) (*v1.Secret, error) {

	var secretsData KubernetesSecretsData
	if rootSecret.SecretString != nil {
		jsonErr := json.Unmarshal([]byte(*rootSecret.SecretString), &secretsData)
		// If secret string is plaintext
		if jsonErr != nil {
			secretsData = KubernetesSecretsData{
				secretName: string(*rootSecret.SecretString),
			}
		}
	} else if rootSecret.SecretBinary != nil {
		secretsData = KubernetesSecretsData{
			secretName: string(rootSecret.SecretBinary),
		}
	}

	// Save root vault secret last changed time as a kubernetes label
	slmVersionAnnotationName := "slm.managed-by"
	lastAppliedAtAnnotationName := "slm." + secretName + ".last-applied-at"
	annotations := KubernetesAnnotations{
		lastAppliedAtAnnotationName: strconv.FormatInt(
			rootSecretDescribeOutput.LastChangedDate.Unix(), 10),
		slmVersionAnnotationName: "true",
	}
	for _, tag := range rootSecretDescribeOutput.Tags {
		annotations[*tag.Key] = *tag.Value
	}

	secret, err := secretsClient.Get(context.Background(), kubernetesTarget.Name,
		metaV1.GetOptions{})

	if err != nil {
		if k8serrors.IsNotFound(err) {
			log.Info("Creating new secret: " + kubernetesTarget.Name + ", ns: " + namespace + ", cluster: " + kubernetesTarget.Cluster)

			newSecret := &v1.Secret{
				StringData: secretsData,
			}
			newSecret.Name = kubernetesTarget.Name
			newSecret.Namespace = namespace
			newSecret.Annotations = annotations

			newSecret, err := secretsClient.Create(context.Background(), newSecret, metaV1.CreateOptions{})
			if err != nil {
				return nil, newKubernetesError(CreateKubernetesSecretError, secretName, kubernetesTarget.Name, kubernetesTarget.Cluster, namespace, "Error creating kubernetes secret."+err.Error())
			}
			return newSecret, nil
		}

		return nil, newKubernetesError(GetKubernetesSecretError, secretName, kubernetesTarget.Name, kubernetesTarget.Cluster, namespace, "Error getting kubernetes secret: "+err.Error())
	}

	if _, ok := secret.Annotations[lastAppliedAtAnnotationName]; ok {
		lastAppliedAtTimestamp, err := strconv.ParseInt(secret.Annotations[lastAppliedAtAnnotationName], 10, 64)
		if err != nil {
			return nil, newKubernetesError(ParsingKubernetesAnnotationsError, secretName, kubernetesTarget.Name, kubernetesTarget.Cluster, namespace, "Error parsing applied date time for secret. "+err.Error())
		}

		rootUpdatedAt := rootSecretDescribeOutput.LastChangedDate.Unix()
		if !(rootUpdatedAt > lastAppliedAtTimestamp) {
			log.Info("Root secret hasn't changed. No update required for secret: " + secretName + ", kubernetes resource: " + kubernetesTarget.Name + ", ns: " + namespace + ", cluster: " + kubernetesTarget.Cluster)
			return secret, nil
		}
	}

	for annotationName, annotationValue := range annotations {
		secret.Annotations[annotationName] = annotationValue
	}

	if secret.StringData == nil {
		secret.StringData = make(map[string]string, len(secretsData))
	}

	for secretKey, secretValue := range secretsData {
		secret.StringData[secretKey] = secretValue
	}

	log.Info("Adding secret " + secretName + "to kubernetes resource: " + kubernetesTarget.Name + ", ns: " + namespace + ", cluster: " + kubernetesTarget.Cluster)

	updatedSecret, err := secretsClient.Update(context.Background(), secret, metaV1.UpdateOptions{})
	if err != nil {
		return nil, newKubernetesError(UpdateKubernetesSecretError, secretName, kubernetesTarget.Name, kubernetesTarget.Cluster, namespace, "Error updating kubernetes secret."+err.Error())

	}

	return updatedSecret, nil
}

func (kubernetesTarget *KubernetesTarget) IsEmpty() bool {
	return kubernetesTarget.Name == "" &&
		len(kubernetesTarget.Namespace) == 0 &&
		kubernetesTarget.Cluster == ""
}

type KubernetesSecretsData map[string]string

type KubernetesAnnotations map[string]string

type AccountRole string

type SecretsManagerIntakeSource struct {
	Name string
}

func (source *SecretsManagerIntakeSource) Validate() error {
	if len(source.Name) <= 0 {
		return errors.New(`Missing intake source name`)
	}
	return nil
}

func getKubernetesClient(cluster string, accountRole AccountRole) (*kubernetes.Clientset, error) {
	if accountRole == "" {
		kubeConfig, err := buildConfigFromFlags(cluster, os.Getenv("KUBECONFIG"))
		if err != nil {
			return nil, err
		}

		kubernetesClient, err := kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			return nil, err
		}

		return kubernetesClient, nil
	}
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"),
	}))
	eksCreds := stscreds.NewCredentials(sess, string(accountRole))

	eksSvc := eks.New(sess, &aws.Config{
		Credentials: eksCreds,
		Region:      aws.String("us-east-1"),
	})

	input := &eks.DescribeClusterInput{
		Name: aws.String(cluster),
	}

	result, err := eksSvc.DescribeCluster(input)
	if err != nil {
		return nil, errors.New("Error describing clusters: " + err.Error())
	}
	clientset, err := newClientset(result.Cluster, accountRole)

	if err != nil {
		return nil, errors.New("Error getting clientset: " + err.Error())
	}
	return clientset, nil
}

func buildConfigFromFlags(context, kubeconfigPath string) (*rest.Config, error) {
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{
			CurrentContext: context,
		}).ClientConfig()
}

func newClientset(cluster *eks.Cluster, accountRole AccountRole) (*kubernetes.Clientset, error) {
	tokGen, err := token.NewGenerator(true, false)
	if err != nil {
		return nil, errors.New("Error getting token generator: " + err.Error())
	}
	opts := &token.GetTokenOptions{
		ClusterID:     aws.StringValue(cluster.Name),
		AssumeRoleARN: string(accountRole),
	}
	tok, err := tokGen.GetWithOptions(opts)
	if err != nil {
		return nil, errors.New("Failed to get token: " + err.Error())
	}
	ca, err := base64.StdEncoding.DecodeString(aws.StringValue(cluster.CertificateAuthority.Data))
	if err != nil {
		return nil, errors.New("Failed to decode CA data: " + err.Error())
	}
	clientset, err := kubernetes.NewForConfig(
		&rest.Config{
			Host:        aws.StringValue(cluster.Endpoint),
			BearerToken: tok.Token,
			TLSClientConfig: rest.TLSClientConfig{
				CAData: ca,
			},
		},
	)
	if err != nil {
		return nil, errors.New("Failed to initialize config: " + err.Error())
	}
	return clientset, nil
}
