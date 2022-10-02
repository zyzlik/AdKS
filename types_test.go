package manager

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/secretsmanager"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	corev1 "k8s.io/client-go/applyconfigurations/core/v1"
)

type MockSecretClient struct {
	Name      string
	Namespace string
}

func (m *MockSecretClient) BuildMockSecret() *v1.Secret {
	mockSecret := &v1.Secret{}
	mockSecret.Name = m.Name
	mockSecret.Namespace = m.Namespace
	mockSecret.Annotations = map[string]string{}
	return mockSecret
}

func (m *MockSecretClient) Create(ctx context.Context, secret *v1.Secret, opts metav1.CreateOptions) (*v1.Secret, error) {
	mockSecret := m.BuildMockSecret()
	return mockSecret, nil
}
func (m *MockSecretClient) Update(ctx context.Context, secret *v1.Secret, opts metav1.UpdateOptions) (*v1.Secret, error) {
	mockSecret := m.BuildMockSecret()
	return mockSecret, nil
}
func (m *MockSecretClient) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return nil
}
func (m *MockSecretClient) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	return nil
}
func (m *MockSecretClient) Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.Secret, error) {
	mockSecret := m.BuildMockSecret()
	return mockSecret, nil
}
func (m *MockSecretClient) List(ctx context.Context, opts metav1.ListOptions) (*v1.SecretList, error) {
	mockSecret := m.BuildMockSecret()
	secretList := &v1.SecretList{
		Items: []v1.Secret{*mockSecret},
	}

	return secretList, nil
}
func (m *MockSecretClient) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return nil, nil
}
func (m *MockSecretClient) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.Secret, err error) {
	mockSecret := m.BuildMockSecret()
	return mockSecret, nil
}
func (m *MockSecretClient) Apply(ctx context.Context, secret *corev1.SecretApplyConfiguration, opts metav1.ApplyOptions) (result *v1.Secret, err error) {
	mockSecret := m.BuildMockSecret()
	return mockSecret, nil
}

func TestMain(m *testing.M) {
	if os.Getenv("ENABLE_TEST_LOGGING") != "1" {
		log.SetOutput(ioutil.Discard)
		log.SetFormatter(&log.JSONFormatter{})
	}
	code := m.Run()
	os.Exit(code)
}

func TestApplyKubernetesManifestSuccess(t *testing.T) {
	testNamespace := []string{"TestNamespace"}
	target := &KubernetesTarget{
		AccountRole: "TestRole",
		Cluster:     "TestCluster",
		Namespace:   testNamespace,
		Name:        "TestName",
	}
	secretName := "TestSecretName"
	createdDate := time.Now()
	lastChangedDate := time.Now()
	output := &secretsmanager.GetSecretValueOutput{
		CreatedDate: &createdDate,
	}
	describeOutput := &secretsmanager.DescribeSecretOutput{
		LastChangedDate: &lastChangedDate,
	}

	secretClient := &MockSecretClient{
		Name:      secretName,
		Namespace: "TestNamespace",
	}
	secret, err := target.ApplyKubernetesManifest(secretClient, testNamespace[0], secretName, output, describeOutput)
	assert.Equal(t, nil, err)
	assert.Equal(t, secretName, secret.Name)
	assert.Equal(t, "TestNamespace", secret.Namespace)
}

func TestKubernetesTargetDeliverSecretNotFound(t *testing.T) {
	testNamespace := []string{"TestNamespace"}
	mockTarget := &KubernetesTarget{
		AccountRole: "TestRole",
		Cluster:     "TestCluster",
		Namespace:   testNamespace,
		Name:        "test-secret",
	}
	mockSecret := &Secret{
		Name: "test-secret",
	}
	mockVault := &MockVault{
		Error: &secretsmanager.ResourceNotFoundException{},
	}
	var shape Shape
	shape = "plaintext"
	err := mockTarget.Deliver(mockVault, "test-stage", mockSecret.Name, shape)
	mockError := newSecretsManagerError(GetSecretValueError,
		"root-vault/test-secret/test-stage", mockSecret.Name,
		"Failed to get secret in root vault during kubernetes delivery. ResourceNotFoundException: ")

	assert.Equal(t, []error{mockError}, err)
}

func TestShape(t *testing.T) {
	var shape Shape
	shape = "binary"
	assert.Equal(t, true, shape.IsBinary())
	assert.Equal(t, false, shape.IsPlaintext())
	assert.Equal(t, false, shape.IsKeyValue())
	shape = "plaintext"
	assert.Equal(t, true, shape.IsPlaintext())
	assert.Equal(t, false, shape.IsBinary())
	assert.Equal(t, false, shape.IsKeyValue())
	shape = "key-value"
	assert.Equal(t, true, shape.IsKeyValue())
	assert.Equal(t, false, shape.IsBinary())
	assert.Equal(t, false, shape.IsPlaintext())
}
