package manager

import (
	"io/ioutil"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"

	"testing"
)

type MockVault struct {
	Error                   awserr.Error
	GetSecretValueOutput    *secretsmanager.GetSecretValueOutput
	PutSecretValueOutput    *secretsmanager.PutSecretValueOutput
	DescribeSecretOutput    *secretsmanager.DescribeSecretOutput
	CreateSecretOutput      *secretsmanager.CreateSecretOutput
	UpdateSecretOutput      *secretsmanager.UpdateSecretOutput
	TagResourceOutput       *secretsmanager.TagResourceOutput
	GetResourcePolicyOutput *secretsmanager.GetResourcePolicyOutput
	PutResourcePolicyOutput *secretsmanager.PutResourcePolicyOutput
}

func (m *MockVault) CreateSecret(input *secretsmanager.CreateSecretInput) (*secretsmanager.CreateSecretOutput, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.CreateSecretOutput, nil

}

func (m *MockVault) DescribeSecret(input *secretsmanager.DescribeSecretInput) (*secretsmanager.DescribeSecretOutput, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.DescribeSecretOutput, nil
}

func (m *MockVault) PutSecretValue(input *secretsmanager.PutSecretValueInput) (*secretsmanager.PutSecretValueOutput, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.PutSecretValueOutput, nil
}

func (m *MockVault) GetSecretValue(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.GetSecretValueOutput, nil
}

func (m *MockVault) UpdateSecret(input *secretsmanager.UpdateSecretInput) (*secretsmanager.UpdateSecretOutput, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.UpdateSecretOutput, nil
}

func (m *MockVault) TagResource(input *secretsmanager.TagResourceInput) (*secretsmanager.TagResourceOutput, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.TagResourceOutput, nil
}

func (m *MockVault) GetResourcePolicy(input *secretsmanager.GetResourcePolicyInput) (*secretsmanager.GetResourcePolicyOutput, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.GetResourcePolicyOutput, nil
}

func (m *MockVault) PutResourcePolicy(input *secretsmanager.PutResourcePolicyInput) (*secretsmanager.PutResourcePolicyOutput, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.PutResourcePolicyOutput, nil
}

func TestGetSecretFromVaultFailure(t *testing.T) {
	mockError := awserr.New("DecryptionFailure",
		"Error decryption secret", nil)
	mockVault := &MockVault{
		Error: mockError,
	}
	_, err := GetSecretFromVault(mockVault, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String("fake-secret"),
	})
	assert.Equal(t, "DecryptionFailure: Error decryption secret", err.Error())
}

func TestGetSecretFromVaultSuccess(t *testing.T) {
	vault := &MockVault{}
	vault.GetSecretValueOutput = &secretsmanager.GetSecretValueOutput{
		Name: aws.String("fake-secret"),
	}

	secret, err := GetSecretFromVault(vault, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String("fake-secret"),
	})
	assert.Equal(t, "fake-secret", *secret.Name)
	assert.Equal(t, nil, err)
}

func TestDoDeliverSuccess(t *testing.T) {
	config, err := ioutil.ReadFile("./example.yaml")
	if err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(2)
	}
	specs := SecretList{}
	err = yaml.Unmarshal(config, &specs)
	if err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(3)
	}

	root := &MockVault{}

	DoDeliver(root, specs.Secrets)
}

func TestSortTags(t *testing.T) {
	atags := []*secretsmanager.Tag{}
	atags = append(atags, &secretsmanager.Tag{
		Key:   aws.String("slm.version"),
		Value: aws.String("v1"),
	})

	atags = append(atags, &secretsmanager.Tag{
		Key:   aws.String("slm.managed-by"),
		Value: aws.String("true"),
	})

	sorted := SortTags(atags)
	expected := []*secretsmanager.Tag{}
	expected = append(expected, &secretsmanager.Tag{
		Key:   aws.String("slm.managed-by"),
		Value: aws.String("true"),
	})
	expected = append(expected, &secretsmanager.Tag{
		Key:   aws.String("slm.version"),
		Value: aws.String("v1"),
	})

	assert.Equal(t, expected, sorted)
}

func TestShouldUpdateTagsFalse(t *testing.T) {
	sourceTags := []*secretsmanager.Tag{}
	sourceTags = append(sourceTags, &secretsmanager.Tag{
		Key:   aws.String("slm.managed-by"),
		Value: aws.String("true"),
	})
	sourceTags = append(sourceTags, &secretsmanager.Tag{
		Key:   aws.String("slm.version"),
		Value: aws.String("v1"),
	})

	sortedSourceTags := SortTags(sourceTags)
	targetTags := []*secretsmanager.Tag{}
	targetTags = append(targetTags, &secretsmanager.Tag{
		Key:   aws.String("slm.managed-by"),
		Value: aws.String("true"),
	})
	targetTags = append(targetTags, &secretsmanager.Tag{
		Key:   aws.String("slm.version"),
		Value: aws.String("v1"),
	})
	sortedTargetTags := SortTags(targetTags)
	shouldUpdate := ShouldUpdateTags(sortedSourceTags, sortedTargetTags)

	assert.Equal(t, false, shouldUpdate)
}

func TestShouldUpdateTagsDifferentLengthTrue(t *testing.T) {
	sourceTags := []*secretsmanager.Tag{}
	sourceTags = append(sourceTags, &secretsmanager.Tag{
		Key:   aws.String("slm.managed-by"),
		Value: aws.String("true"),
	})
	sourceTags = append(sourceTags, &secretsmanager.Tag{
		Key:   aws.String("slm.version"),
		Value: aws.String("v1"),
	})
	sourceTags = append(sourceTags, &secretsmanager.Tag{
		Key:   aws.String("owner"),
		Value: aws.String("foundations"),
	})

	sortedSourceTags := SortTags(sourceTags)
	targetTags := []*secretsmanager.Tag{}
	targetTags = append(targetTags, &secretsmanager.Tag{
		Key:   aws.String("slm.managed-by"),
		Value: aws.String("true"),
	})
	targetTags = append(targetTags, &secretsmanager.Tag{
		Key:   aws.String("slm.version"),
		Value: aws.String("v2"),
	})
	sortedTargetTags := SortTags(targetTags)
	shouldUpdate := ShouldUpdateTags(sortedSourceTags, sortedTargetTags)

	assert.Equal(t, true, shouldUpdate)
}

func TestShouldUpdateTargetDoesExist(t *testing.T) {
	fakeSourceOutput := &secretsmanager.DescribeSecretOutput{}
	fakeTargetOutput := &secretsmanager.DescribeSecretOutput{}
	fakeCurrentPolicy := aws.String("fakeCurrentPolicy")
	fakeTargetPolicy := &secretsmanager.GetResourcePolicyOutput{}
	fakeKmsKeyId := "fakeKmsKey"
	fakeTags := []*secretsmanager.Tag{{
		Key:   aws.String("FakeKey"),
		Value: aws.String("FakeValue"),
	}}
	assert.Equal(t, true, ShouldUpdate(fakeSourceOutput, fakeTargetOutput,
		fakeCurrentPolicy, fakeTargetPolicy,
		fakeKmsKeyId, fakeTags,
		true,
	))

}

func TestShouldUpdateTargetExistsNoChanges(t *testing.T) {
	fakeLastChangedDate := time.Date(
		2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	fakeSourceOutput := &secretsmanager.DescribeSecretOutput{
		ARN:             aws.String("Fake ARN"),
		LastChangedDate: &fakeLastChangedDate,
	}
	fakeTargetOutput := &secretsmanager.DescribeSecretOutput{
		KmsKeyId:        aws.String("fakeKmsKey"),
		LastChangedDate: &fakeLastChangedDate,
		Tags: []*secretsmanager.Tag{{
			Key:   aws.String("FakeKey"),
			Value: aws.String("FakeValue"),
		}},
	}
	fakeCurrentPolicy := aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"secretsmanager:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotLike\":{\"aws:PrincipalArn\":[\"fake arn principals\"]}}}]}")
	fakeTargetPolicy := &secretsmanager.GetResourcePolicyOutput{
		ResourcePolicy: fakeCurrentPolicy,
	}
	fakeKmsKeyId := "fakeKmsKey"
	fakeTags := []*secretsmanager.Tag{{
		Key:   aws.String("FakeKey"),
		Value: aws.String("FakeValue"),
	}}
	assert.Equal(t, false, ShouldUpdate(fakeSourceOutput, fakeTargetOutput,
		fakeCurrentPolicy, fakeTargetPolicy,
		fakeKmsKeyId, fakeTags,
		false,
	))

}

func TestShouldUpdateTargetExistsNoTargetResourcePolicy(t *testing.T) {
	fakeLastChangedDate := time.Date(
		2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	fakeSourceOutput := &secretsmanager.DescribeSecretOutput{
		ARN:             aws.String("Fake ARN"),
		LastChangedDate: &fakeLastChangedDate,
	}
	fakeTargetOutput := &secretsmanager.DescribeSecretOutput{
		KmsKeyId:        aws.String("fakeKmsKey"),
		LastChangedDate: &fakeLastChangedDate,
		Tags: []*secretsmanager.Tag{{
			Key:   aws.String("FakeKey"),
			Value: aws.String("FakeValue"),
		}},
	}
	fakeCurrentPolicy := aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"secretsmanager:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotLike\":{\"aws:PrincipalArn\":[\"fake arn principals\"]}}}]}")
	fakeTargetPolicy := &secretsmanager.GetResourcePolicyOutput{}
	fakeKmsKeyId := "fakeKmsKey"
	fakeTags := []*secretsmanager.Tag{{
		Key:   aws.String("FakeKey"),
		Value: aws.String("FakeValue"),
	}}
	assert.Equal(t, true, ShouldUpdate(fakeSourceOutput, fakeTargetOutput,
		fakeCurrentPolicy, fakeTargetPolicy,
		fakeKmsKeyId, fakeTags,
		false,
	))

}

func TestShouldUpdateTargetExistsSourceResourcePolicyChanged(t *testing.T) {
	fakeLastChangedDate := time.Date(
		2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	fakeSourceOutput := &secretsmanager.DescribeSecretOutput{
		ARN:             aws.String("Fake ARN"),
		LastChangedDate: &fakeLastChangedDate,
	}
	fakeTargetOutput := &secretsmanager.DescribeSecretOutput{
		KmsKeyId:        aws.String("fakeKmsKey"),
		LastChangedDate: &fakeLastChangedDate,
		Tags: []*secretsmanager.Tag{{
			Key:   aws.String("FakeKey"),
			Value: aws.String("FakeValue"),
		}},
	}
	fakeCurrentPolicy := aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"secretsmanager:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotLike\":{\"aws:PrincipalArn\":[\"fake policy arn\"]}}}]}")
	fakeTargetPolicy := aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"secretsmanager:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotLike\":{\"aws:PrincipalArn\":[\"fake policy arn\", \"new fake policy arn\"]}}}]}")
	fakeTargetPolicyOutput := &secretsmanager.GetResourcePolicyOutput{
		ResourcePolicy: fakeTargetPolicy,
	}
	fakeKmsKeyId := "fakeKmsKey"
	fakeTags := []*secretsmanager.Tag{{
		Key:   aws.String("FakeKey"),
		Value: aws.String("FakeValue"),
	}}
	assert.Equal(t, true, ShouldUpdate(fakeSourceOutput, fakeTargetOutput,
		fakeCurrentPolicy, fakeTargetPolicyOutput,
		fakeKmsKeyId, fakeTags,
		false,
	))

}

func TestShouldUpdateTargetExistsStaleTargetLastChangedDate(t *testing.T) {
	fakeLastChangedDate := time.Date(
		2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	fakeTargetLastChangedDate := time.Date(
		2009, 11, 15, 20, 34, 58, 651387237, time.UTC)

	fakeSourceOutput := &secretsmanager.DescribeSecretOutput{
		ARN:             aws.String("Fake ARN"),
		LastChangedDate: &fakeLastChangedDate,
	}
	fakeTargetOutput := &secretsmanager.DescribeSecretOutput{
		KmsKeyId:        aws.String("fakeKmsKey"),
		LastChangedDate: &fakeTargetLastChangedDate,
		Tags: []*secretsmanager.Tag{{
			Key:   aws.String("FakeKey"),
			Value: aws.String("FakeValue"),
		}},
	}
	fakeCurrentPolicy := aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"secretsmanager:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotLike\":{\"aws:PrincipalArn\":[\"fake arn principals\"]}}}]}")
	fakeTargetPolicy := &secretsmanager.GetResourcePolicyOutput{}
	fakeKmsKeyId := "fakeKmsKey"
	fakeTags := []*secretsmanager.Tag{{
		Key:   aws.String("FakeKey"),
		Value: aws.String("FakeValue"),
	}}
	assert.Equal(t, true, ShouldUpdate(fakeSourceOutput, fakeTargetOutput,
		fakeCurrentPolicy, fakeTargetPolicy,
		fakeKmsKeyId, fakeTags,
		false,
	))

}

func TestShouldUpdateTargetExistsNewSourceTags(t *testing.T) {
	fakeLastChangedDate := time.Date(
		2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	fakeSourceOutput := &secretsmanager.DescribeSecretOutput{
		ARN:             aws.String("Fake ARN"),
		LastChangedDate: &fakeLastChangedDate,
	}
	fakeTargetOutput := &secretsmanager.DescribeSecretOutput{
		KmsKeyId:        aws.String("fakeKmsKey"),
		LastChangedDate: &fakeLastChangedDate,
		Tags: []*secretsmanager.Tag{{
			Key:   aws.String("FakeKey"),
			Value: aws.String("FakeValue"),
		}},
	}
	fakeCurrentPolicy := aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"secretsmanager:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotLike\":{\"aws:PrincipalArn\":[\"fake arn principals\"]}}}]}")
	fakeTargetPolicy := &secretsmanager.GetResourcePolicyOutput{
		ResourcePolicy: fakeCurrentPolicy,
	}
	fakeKmsKeyId := "fakeKmsKey"
	fakeTags := []*secretsmanager.Tag{
		{
			Key:   aws.String("FakeKey"),
			Value: aws.String("FakeValue"),
		},
		{
			Key:   aws.String("NewFakeKey"),
			Value: aws.String("NewFakeValue"),
		},
	}
	assert.Equal(t, true, ShouldUpdate(fakeSourceOutput, fakeTargetOutput,
		fakeCurrentPolicy, fakeTargetPolicy,
		fakeKmsKeyId, fakeTags,
		false,
	))

}

func TestDeriveRootVaultSecretName(t *testing.T) {
	assert.Equal(t, "root-vault/fake-secret/alpha", DeriveRootVaultSecretName("fake-secret", "alpha"))
}
