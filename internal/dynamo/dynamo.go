// Package dynamo stores small JSON values in a DynamoDB table.
//
// A [Record] is one item keyed by "lease_id" with the JSON in "value". A write
// succeeds only if "value" still equals the caller's expected JSON, so two NATs
// can never both advance the same record. A [Board] is one item that several
// writers share, each writing its own attribute.
package dynamo

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// API is the subset of the DynamoDB client this package uses. Configure the
// client without retries: a timed-out conditional write may still have been
// applied, and retrying it would report a false conflict.
type API interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

// Record is one item in the table.
type Record struct {
	api   API
	table string
	id    string
}

// NewRecord returns the record with the given ID in table.
func NewRecord(api API, table, id string) Record {
	return Record{api: api, table: table, id: id}
}

// Read returns the record's JSON using a strongly consistent read, or nil if
// the record does not exist.
func (r Record) Read(ctx context.Context) ([]byte, error) {
	output, err := r.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(r.table),
		Key:            r.key(),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read record %q: %w", r.id, err)
	}
	value, ok := output.Item["value"].(*types.AttributeValueMemberS)
	if !ok {
		return nil, nil
	}
	return []byte(value.Value), nil
}

// Swap replaces the record with replacement if its JSON still equals expected.
// A nil expected value requires that the record does not exist. Swap reports
// false without an error when the condition fails.
func (r Record) Swap(ctx context.Context, expected, replacement []byte) (bool, error) {
	item := r.key()
	item["value"] = &types.AttributeValueMemberS{Value: string(replacement)}
	input := &dynamodb.PutItemInput{TableName: aws.String(r.table), Item: item}
	if expected == nil {
		input.ConditionExpression = aws.String("attribute_not_exists(lease_id)")
	} else {
		input.ConditionExpression = aws.String("#value = :expected")
		input.ExpressionAttributeNames = map[string]string{"#value": "value"}
		input.ExpressionAttributeValues = map[string]types.AttributeValue{":expected": &types.AttributeValueMemberS{Value: string(expected)}}
	}
	_, err := r.api.PutItem(ctx, input)
	if err != nil {
		if _, ok := errors.AsType[*types.ConditionalCheckFailedException](err); ok {
			return false, nil
		}
		return false, fmt.Errorf("failed to write record %q: %w", r.id, err)
	}
	return true, nil
}

func (r Record) key() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"lease_id": &types.AttributeValueMemberS{Value: r.id}}
}

// Board is one item that several writers share. Each writes its own attribute,
// and a reader reads them all at once.
type Board struct {
	api   API
	table string
	id    string
}

// NewBoard returns the board with the given ID in table.
func NewBoard(api API, table, id string) Board {
	return Board{api: api, table: table, id: id}
}

// Post sets the attribute name to value, creating the item if needed.
func (b Board) Post(ctx context.Context, name string, value []byte) error {
	return b.update(ctx, "SET #name = :value", name, map[string]types.AttributeValue{":value": &types.AttributeValueMemberS{Value: string(value)}})
}

// Remove deletes the attribute name.
func (b Board) Remove(ctx context.Context, name string) error {
	return b.update(ctx, "REMOVE #name", name, nil)
}

// Read returns every attribute's value using a strongly consistent read.
func (b Board) Read(ctx context.Context) (map[string][]byte, error) {
	output, err := b.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(b.table),
		Key:            Record{id: b.id}.key(),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read board %q: %w", b.id, err)
	}
	values := map[string][]byte{}
	for name, attribute := range output.Item {
		if value, ok := attribute.(*types.AttributeValueMemberS); ok && name != "lease_id" {
			values[name] = []byte(value.Value)
		}
	}
	return values, nil
}

func (b Board) update(ctx context.Context, expression, name string, values map[string]types.AttributeValue) error {
	_, err := b.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(b.table),
		Key:                       Record{id: b.id}.key(),
		UpdateExpression:          aws.String(expression),
		ExpressionAttributeNames:  map[string]string{"#name": name},
		ExpressionAttributeValues: values,
	})
	if err != nil {
		return fmt.Errorf("failed to update board %q: %w", b.id, err)
	}
	return nil
}
