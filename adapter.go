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
	"context"
	"runtime"
	"time"

	"github.com/casbin/casbin/model"
	"github.com/casbin/casbin/persist"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/x/bsonx"
	"go.mongodb.org/mongo-driver/x/mongo/driver"
)

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	PType string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

// adapter represents the MongoDB adapter for policy storage.
type adapter struct {
	url        string
	database   *mongo.Database
	collection *mongo.Collection
	ownClient  bool
	client     *mongo.Client
}

// finalizer is the destructor for adapter.
func finalizer(a *adapter) {
	a.close()
}

// NewAdapter is the constructor for Adapter. If database name is not provided
// in the Mongo URL, 'casbin' will be used as database name.
func NewAdapter(url string) persist.Adapter {
	a := &adapter{url: url}

	// Open the DB, create it if not existed.
	a.open()

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a
}

// NewAdapterWithDB is the constructor for Adapter that uses an already
// existing Mongo DB connection.
func NewAdapterWithDB(thedb *mongo.Database) persist.Adapter {
	a := &adapter{database: thedb}
	a.openWithDB(thedb)

	//no finalizer as the caller will close its connection

	return a
}

func (a *adapter) openWithDB(db *mongo.Database) {
	collection := db.Collection("casbin_rule")
	a.collection = collection

	indexes := []string{"ptype", "v0", "v1", "v2", "v3", "v4", "v5"}
	models := []mongo.IndexModel{}
	opts := options.Index()
	opts.SetBackground(false)
	for _, k := range indexes {
		models = append(models, mongo.IndexModel{Keys: bsonx.Doc{{Key: k, Value: bsonx.Int32(1)}}, Options: opts})
	}
	if _, err := a.collection.Indexes().CreateMany(context.Background(), models); err != nil {
		e, ok := err.(driver.Error)
		if !ok || e.Code != 86 { //IndexKeySpecsConflict
			panic(err)
		}
	}
}

func (a *adapter) open() {
	var err error
	opts := options.Client().ApplyURI(a.url)
	cli, err := mongo.NewClient(opts)
	if err != nil {
		panic(err)
	}
	ctx1, cf1 := context.WithTimeout(context.Background(), 8*time.Second)
	defer cf1()
	if err := cli.Connect(ctx1); err != nil {
		panic(err)
	}
	ctx, cf := context.WithTimeout(context.Background(), 8*time.Second)
	defer cf()
	err = cli.Ping(ctx, readpref.Primary())
	if err != nil {
		panic(err)
	}
	db := cli.Database("casbin_rule")
	a.database = db
	a.ownClient = true
	a.client = cli
	a.openWithDB(db)
}

func (a *adapter) close() {
	if a.ownClient && a.client != nil {
		a.client.Disconnect(context.Background())
	}
}

func (a *adapter) dropTable() error {
	err := a.collection.Drop(context.Background())
	if err != nil {
		if err.Error() != "ns not found" {
			return err
		}
	}
	return nil
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	key := line.PType
	sec := key[:1]

	tokens := []string{}
	if line.V0 != "" {
		tokens = append(tokens, line.V0)
	} else {
		goto LineEnd
	}

	if line.V1 != "" {
		tokens = append(tokens, line.V1)
	} else {
		goto LineEnd
	}

	if line.V2 != "" {
		tokens = append(tokens, line.V2)
	} else {
		goto LineEnd
	}

	if line.V3 != "" {
		tokens = append(tokens, line.V3)
	} else {
		goto LineEnd
	}

	if line.V4 != "" {
		tokens = append(tokens, line.V4)
	} else {
		goto LineEnd
	}

	if line.V5 != "" {
		tokens = append(tokens, line.V5)
	} else {
		goto LineEnd
	}

LineEnd:
	model[sec][key].Policy = append(model[sec][key].Policy, tokens)
}

// LoadPolicy loads policy from database.
func (a *adapter) LoadPolicy(model model.Model) error {
	line := CasbinRule{}
	cur, err := a.collection.Find(context.Background(), bson.M{})
	if err != nil {
		return err
	}
	ctx, cf := context.WithTimeout(context.Background(), 10*time.Second)
	defer cf()
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		err := cur.Decode(&line)
		if err != nil {
			return err
		}
		loadPolicyLine(line, model)
	}
	return cur.Err()
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{
		PType: ptype,
	}

	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

// SavePolicy saves policy to database.
func (a *adapter) SavePolicy(model model.Model) error {
	if err := a.dropTable(); err != nil {
		return err
	}

	var lines []interface{}

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	_, err := a.collection.InsertMany(context.Background(), lines)
	return err
}

// AddPolicy adds a policy rule to the storage.
func (a *adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	_, err := a.collection.InsertOne(context.Background(), line)
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	_, err := a.collection.DeleteOne(context.Background(), line)
	return err
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	selector := bson.M{}
	selector["ptype"] = ptype

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		selector["v0"] = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		selector["v1"] = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		selector["v2"] = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		selector["v3"] = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		selector["v4"] = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		selector["v5"] = fieldValues[5-fieldIndex]
	}

	_, err := a.collection.DeleteMany(context.Background(), selector)
	return err
}
