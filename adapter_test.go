// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mongodbadapter

import (
	"os"
	"testing"

	"github.com/casbin/casbin"
	"github.com/casbin/casbin/util"
)

var testDbURL = os.Getenv("TEST_MONGODB_URL")

func getDbURL() string {
	if testDbURL == "" {
		testDbURL = "127.0.0.1:27017"
	}
	return testDbURL
}

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	myRes := e.GetPolicy()
	t.Log("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func initPolicy(t *testing.T) {
	// Because the DB is empty at first,
	// so we need to load the policy from the file adapter (.CSV) first.
	e := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	a := NewAdapter(getDbURL())
	// This is a trick to save the current policy to the DB.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	err := a.SavePolicy(e.GetModel())
	if err != nil {
		panic(err)
	}

	// Clear the current policy.
	e.ClearPolicy()
	testGetPolicy(t, e, [][]string{})

	// Load the policy from DB.
	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		panic(err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func TestAdapter(t *testing.T) {
	initPolicy(t)

	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a := NewAdapter(getDbURL())
	e := casbin.NewEnforcer("examples/rbac_model.conf", a)
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// AutoSave is enabled by default.
	// Now we disable it.
	e.EnableAutoSave(false)

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// This is still the original policy.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}})

	// Remove the added rule.
	e.RemovePolicy("alice", "data1", "write")
	if err := a.RemovePolicy("p", "p", []string{"alice", "data1", "write"}); err != nil {
		t.Errorf("Expected RemovePolicy() to be successful; got %v", err)
	}
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Remove "data2_admin" related policy rules via a filter.
	// Two rules: {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"} are deleted.
	e.RemoveFilteredPolicy(0, "data2_admin")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})

	e.RemoveFilteredPolicy(1, "data1")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{{"bob", "data2", "write"}})

	e.RemoveFilteredPolicy(2, "write")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{})
}

func TestNewAdapterWithInvalidURL(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected recovery from panic")
		}
	}()

	_ = NewAdapter("localhost:40001?foo=1&bar=2")
}

func TestNewAdapterWithUnknownURL(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected recovery from panic")
		}
	}()

	_ = NewAdapter("fakeserver:27017")
}
