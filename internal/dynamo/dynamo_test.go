package dynamo_test

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/dynamo"
	"github.com/artie-labs/natpair/internal/mocks"
)

func TestRecordRead(t *testing.T) {
	{
		// Missing record
		api := &mocks.FakeDynamoAPI{}
		api.GetItemReturns(&dynamodb.GetItemOutput{}, nil)
		value, err := dynamo.NewRecord(api, "lab-table", "pair/v3/ownership").Read(t.Context())
		require.NoError(t, err)
		assert.Nil(t, value)

		_, input, _ := api.GetItemArgsForCall(0)
		assert.Equal(t, "lab-table", aws.ToString(input.TableName))
		assert.Equal(t, &types.AttributeValueMemberS{Value: "pair/v3/ownership"}, input.Key["lease_id"])
		// The lease depends on reading the latest write.
		assert.True(t, aws.ToBool(input.ConsistentRead))
	}
	{
		// Existing record
		api := &mocks.FakeDynamoAPI{}
		api.GetItemReturns(&dynamodb.GetItemOutput{Item: map[string]types.AttributeValue{
			"value": &types.AttributeValueMemberS{Value: `{"state":"clear"}`},
		}}, nil)
		value, err := dynamo.NewRecord(api, "lab-table", "pair/v3/ownership").Read(t.Context())
		require.NoError(t, err)
		assert.JSONEq(t, `{"state":"clear"}`, string(value))
	}
}

func TestRecordSwap(t *testing.T) {
	{
		// Replace an exact expected value
		api := &mocks.FakeDynamoAPI{}
		api.PutItemReturns(&dynamodb.PutItemOutput{}, nil)
		ok, err := dynamo.NewRecord(api, "lab-table", "pair/v3/ownership").Swap(t.Context(), []byte(`{"epoch":1}`), []byte(`{"epoch":2}`))
		require.NoError(t, err)
		assert.True(t, ok)

		_, input, _ := api.PutItemArgsForCall(0)
		assert.Equal(t, map[string]types.AttributeValue{
			"lease_id": &types.AttributeValueMemberS{Value: "pair/v3/ownership"},
			"value":    &types.AttributeValueMemberS{Value: `{"epoch":2}`},
		}, input.Item)
		assert.Equal(t, "#value = :expected", aws.ToString(input.ConditionExpression))
		assert.Equal(t, map[string]string{"#value": "value"}, input.ExpressionAttributeNames)
		assert.Equal(t, &types.AttributeValueMemberS{Value: `{"epoch":1}`}, input.ExpressionAttributeValues[":expected"])
	}
	{
		// A nil expected value requires that the record does not exist
		api := &mocks.FakeDynamoAPI{}
		api.PutItemReturns(&dynamodb.PutItemOutput{}, nil)
		_, err := dynamo.NewRecord(api, "lab-table", "pair/v3/ownership").Swap(t.Context(), nil, []byte(`{}`))
		require.NoError(t, err)
		_, input, _ := api.PutItemArgsForCall(0)
		assert.Equal(t, "attribute_not_exists(lease_id)", aws.ToString(input.ConditionExpression))
	}
	{
		// A failed condition is a normal outcome, reported once without retrying
		api := &mocks.FakeDynamoAPI{}
		api.PutItemReturns(nil, &types.ConditionalCheckFailedException{})
		ok, err := dynamo.NewRecord(api, "lab-table", "pair/v3/ownership").Swap(t.Context(), nil, []byte(`{}`))
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Equal(t, 1, api.PutItemCallCount())
	}
	{
		// Other errors are returned
		api := &mocks.FakeDynamoAPI{}
		api.PutItemReturns(nil, errors.New("timeout"))
		_, err := dynamo.NewRecord(api, "lab-table", "pair/v3/ownership").Swap(t.Context(), nil, []byte(`{}`))
		assert.ErrorContains(t, err, `failed to write record "pair/v3/ownership": timeout`)
	}
}

func TestBoard(t *testing.T) {
	{
		// Each writer sets only its own attribute
		api := &mocks.FakeDynamoAPI{}
		api.UpdateItemReturns(&dynamodb.UpdateItemOutput{}, nil)
		require.NoError(t, dynamo.NewBoard(api, "lab-table", "pair/v3/health").Post(t.Context(), "nat:i-a", []byte(`{"seq":1}`)))
		_, input, _ := api.UpdateItemArgsForCall(0)
		assert.Equal(t, &types.AttributeValueMemberS{Value: "pair/v3/health"}, input.Key["lease_id"])
		assert.Equal(t, "SET #name = :value", aws.ToString(input.UpdateExpression))
		assert.Equal(t, map[string]string{"#name": "nat:i-a"}, input.ExpressionAttributeNames)
		assert.Equal(t, &types.AttributeValueMemberS{Value: `{"seq":1}`}, input.ExpressionAttributeValues[":value"])

		require.NoError(t, dynamo.NewBoard(api, "lab-table", "pair/v3/health").Remove(t.Context(), "nat:i-old"))
		_, input, _ = api.UpdateItemArgsForCall(1)
		assert.Equal(t, "REMOVE #name", aws.ToString(input.UpdateExpression))
		assert.Equal(t, map[string]string{"#name": "nat:i-old"}, input.ExpressionAttributeNames)
	}
	{
		// A read returns every writer's value, without the key
		api := &mocks.FakeDynamoAPI{}
		api.GetItemReturns(&dynamodb.GetItemOutput{Item: map[string]types.AttributeValue{
			"lease_id": &types.AttributeValueMemberS{Value: "pair/v3/health"},
			"nat:i-a":  &types.AttributeValueMemberS{Value: `{"seq":1}`},
			"nat:i-b":  &types.AttributeValueMemberS{Value: `{"seq":2}`},
		}}, nil)
		values, err := dynamo.NewBoard(api, "lab-table", "pair/v3/health").Read(t.Context())
		require.NoError(t, err)
		assert.Equal(t, map[string][]byte{"nat:i-a": []byte(`{"seq":1}`), "nat:i-b": []byte(`{"seq":2}`)}, values)
		_, input, _ := api.GetItemArgsForCall(0)
		assert.True(t, aws.ToBool(input.ConsistentRead))
	}
	{
		// Errors are reported
		api := &mocks.FakeDynamoAPI{}
		api.UpdateItemReturns(nil, errors.New("throttled"))
		assert.ErrorContains(t, dynamo.NewBoard(api, "lab-table", "pair/v3/health").Post(t.Context(), "nat:i-a", nil), "throttled")
	}
}
