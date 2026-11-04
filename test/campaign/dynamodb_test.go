//go:build linux && campaign

package campaign

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// fakeDynamoDB serves GetItem, PutItem and UpdateItem with the same conditional
// rules as DynamoDB, for the expressions natpair uses. The NATs run their
// real AWS SDK client against it.
type fakeDynamoDB struct {
	mu    sync.Mutex
	items map[string]map[string]attribute
	// updated is when UpdateItem last set each item's attribute.
	updated map[[2]string]time.Time
}

type attribute struct {
	S string `json:"S,omitempty"`
	N string `json:"N,omitempty"`
}

type put struct {
	TableName                 string               `json:"TableName"`
	Item                      map[string]attribute `json:"Item"`
	ConditionExpression       string               `json:"ConditionExpression"`
	ExpressionAttributeNames  map[string]string    `json:"ExpressionAttributeNames"`
	ExpressionAttributeValues map[string]attribute `json:"ExpressionAttributeValues"`
}

func newFakeDynamoDB() *fakeDynamoDB {
	return &fakeDynamoDB{items: map[string]map[string]attribute{}, updated: map[[2]string]time.Time{}}
}

func (f *fakeDynamoDB) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var status int
	var body []byte
	request, err := io.ReadAll(r.Body)
	if err == nil {
		f.mu.Lock()
		status, body = f.handle(strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "DynamoDB_20120810."), request)
		f.mu.Unlock()
	} else {
		status, body = errorBody("ValidationException", err.Error())
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	// Real DynamoDB sends a CRC32 of every body in a header, and the SDK checks it.
	w.Header().Set("X-Amz-Crc32", strconv.FormatUint(uint64(crc32.ChecksumIEEE(body)), 10))
	w.WriteHeader(status)
	w.Write(body)
}

func (f *fakeDynamoDB) handle(target string, body []byte) (int, []byte) {
	switch target {
	case "GetItem":
		var request struct {
			Key map[string]attribute `json:"Key"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			return errorBody("ValidationException", err.Error())
		}
		item, ok := f.items[request.Key["lease_id"].S]
		if !ok {
			return http.StatusOK, []byte(`{}`)
		}
		encoded, _ := json.Marshal(map[string]any{"Item": item})
		return http.StatusOK, encoded
	case "PutItem":
		var request put
		if err := json.Unmarshal(body, &request); err != nil {
			return errorBody("ValidationException", err.Error())
		}
		if !f.matches(request.Item["lease_id"].S, request.ConditionExpression, request.ExpressionAttributeNames, request.ExpressionAttributeValues) {
			return errorBody("ConditionalCheckFailedException", "The conditional request failed")
		}
		f.items[request.Item["lease_id"].S] = request.Item
		return http.StatusOK, []byte(`{}`)
	case "UpdateItem":
		// The board sets or removes one attribute per update.
		var request struct {
			Key                       map[string]attribute `json:"Key"`
			UpdateExpression          string               `json:"UpdateExpression"`
			ExpressionAttributeNames  map[string]string    `json:"ExpressionAttributeNames"`
			ExpressionAttributeValues map[string]attribute `json:"ExpressionAttributeValues"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			return errorBody("ValidationException", err.Error())
		}
		id := request.Key["lease_id"].S
		item, ok := f.items[id]
		if !ok {
			item = map[string]attribute{"lease_id": {S: id}}
			f.items[id] = item
		}
		name := request.ExpressionAttributeNames["#name"]
		switch request.UpdateExpression {
		case "SET #name = :value":
			item[name] = request.ExpressionAttributeValues[":value"]
			f.updated[[2]string{id, name}] = time.Now()
		case "REMOVE #name":
			delete(item, name)
		default:
			return errorBody("ValidationException", "unsupported update expression "+request.UpdateExpression)
		}
		return http.StatusOK, []byte(`{}`)
	default:
		return errorBody("UnknownOperationException", fmt.Sprintf("unsupported operation %q", target))
	}
}

// attributes returns the string attributes of item id whose names start with
// prefix, with when each was last set.
func (f *fakeDynamoDB) attributes(id, prefix string) map[string]postedValue {
	f.mu.Lock()
	defer f.mu.Unlock()
	values := map[string]postedValue{}
	for name, value := range f.items[id] {
		if strings.HasPrefix(name, prefix) {
			values[name] = postedValue{value: value.S, at: f.updated[[2]string{id, name}]}
		}
	}
	return values
}

type postedValue struct {
	value string
	at    time.Time
}

// matches evaluates a condition, either attribute_not_exists(lease_id) or
// "#name = :value".
func (f *fakeDynamoDB) matches(id, expression string, names map[string]string, values map[string]attribute) bool {
	if expression == "" {
		return true
	}
	item, exists := f.items[id]
	if expression == "attribute_not_exists(lease_id)" {
		return !exists
	}
	left, right, ok := strings.Cut(expression, " = ")
	return ok && exists && item[names[left]] == values[right]
}

func errorBody(code, message string) (int, []byte) {
	encoded, _ := json.Marshal(map[string]any{"__type": "com.amazonaws.dynamodb.v20120810#" + code, "message": message})
	return http.StatusBadRequest, encoded
}
