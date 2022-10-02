package manager

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
)

type SecretsManagerErrorType int64
type KubernetesErrorType int64
type SchemaErrorType int64

const (
	SecretDoesNotExistError SecretsManagerErrorType = iota
	GetSecretValueError
	UpdateSecretError
	CreateSecretError
	UpdateSecretTagsError
	UpdateSecretPolicyError
	AllowedPrincipalsMarshalError
	SecretInputValidationError
	GetSecretPolicyError
)

const (
	GetKubernetesSecretError KubernetesErrorType = iota
	CreateKubernetesSecretError
	UpdateKubernetesSecretError
	ParsingKubernetesAnnotationsError
	ApplySecretError
)

const (
	ValidationError SchemaErrorType = iota
)

func (s SecretsManagerErrorType) String() string {
	switch s {
	case SecretDoesNotExistError:
		return "SOURCE_DOES_NOT_EXIST_ERROR"
	case GetSecretValueError:
		return "SOURCE_GET_VALUE_ERROR"
	case UpdateSecretError:
		return "UPDATE_SECRET_ERROR"
	case CreateSecretError:
		return "CREATE_SECRET_ERROR"
	case UpdateSecretTagsError:
		return "UPDATE_SECRET_TAGS_ERROR"
	case UpdateSecretPolicyError:
		return "UPDATE_SECRET_POLICY_ERROR"
	case GetSecretPolicyError:
		return "GET_SECRET_POLICY_ERROR"
	case SecretInputValidationError:
		return "SECRET_INPUT_VALIDATION_ERROR"
	case AllowedPrincipalsMarshalError:
		return "ALLOWED_PRINCIPALS_MARSHAL_ERROR"
	}
	return "UNKNOWN"
}

func (k KubernetesErrorType) String() string {
	switch k {
	case GetKubernetesSecretError:
		return "GET_KUBERNETES_SECRET_ERROR"
	case CreateKubernetesSecretError:
		return "CREATE_KUBERNETES_SECRET_ERROR"
	case UpdateKubernetesSecretError:
		return "UPDATE_KUBERNETES_SECRET_ERROR"
	case ParsingKubernetesAnnotationsError:
		return "PARSING_KUBERNETES_ANNOTATION_ERROR"
	case ApplySecretError:
		return "APPLY_SECRET_ERROR"
	}
	return "UNKNOWN"
}

func (sch SchemaErrorType) String() string {
	switch sch {
	case ValidationError:
		return "VALIDATION_ERROR"
	}
	return "UNKNOWN"
}

type KubernetesError struct {
	ErrorType        KubernetesErrorType
	SourceSecretName string
	TargetSecretName string
	Cluster          string
	Namespace        string
	Message          string
}

func (k KubernetesError) Error() string {
	return k.ErrorType.String() + ": Kubernetes delivery for secret " + k.SourceSecretName + " to target " +
		k.TargetSecretName + " in cluster " + k.Cluster + " for namespace " + k.Namespace + " failed: " + k.Message + "."
}

func newKubernetesError(errorType KubernetesErrorType,
	sourceName, targetName, cluster,
	namespace, message string) *KubernetesError {
	return &KubernetesError{
		ErrorType:        errorType,
		SourceSecretName: sourceName,
		TargetSecretName: targetName,
		Cluster:          cluster,
		Namespace:        namespace,
		Message:          message,
	}

}

type SecretsManagerError struct {
	ErrorType        SecretsManagerErrorType
	AwsError         awserr.Error
	SourceSecretName string
	TargetSecretName string
	Message          string
}

func (s SecretsManagerError) Error() string {
	return s.ErrorType.String() + ": Secret manager delivery for secret " + s.SourceSecretName + " to target " +
		s.TargetSecretName + " failed: " + s.Message + ": " + s.AwsError.Message()
}

func newSecretsManagerError(errorType SecretsManagerErrorType,
	sourceName, targetName, message string) *SecretsManagerError {
	return &SecretsManagerError{
		ErrorType:        errorType,
		SourceSecretName: sourceName,
		TargetSecretName: targetName,
		Message:          message,
	}
}

type SchemaError struct {
	ErrorType  SchemaErrorType
	SecretName string
	Message    string
}

func (se SchemaError) Error() string {
	return se.ErrorType.String() + ": Error in schema for secret " + se.SecretName + ": " + se.Message + "."
}

func newSchemaError(errorType SchemaErrorType,
	secretName, message string) *SchemaError {
	return &SchemaError{
		ErrorType:  errorType,
		SecretName: secretName,
		Message:    message,
	}
}