//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"strings"
)

// Uniq is a collection of unique elements.
type Uniq map[string]struct{}

func NewUniq() Uniq {
	return make(Uniq)
}

func (u Uniq) Add(elements ...string) {
	for _, e := range elements {
		u[e] = struct{}{}
	}
}

func (u Uniq) Values() []string {
	var result []string
	for k := range u {
		result = append(result, k)
	}
	return result
}

// Intersect returns the intersection of two collections.
func (u Uniq) Intersect(other Uniq) Uniq {
	result := make(Uniq)
	for k := range u {
		if _, ok := other[k]; ok {
			result[k] = struct{}{}
		}
	}
	return result
}

// Union returns the union of two collections.
func (u Uniq) Union(other Uniq) Uniq {
	result := make(Uniq)
	for k := range u {
		result[k] = struct{}{}
	}
	for k := range other {
		result[k] = struct{}{}
	}
	return result
}

// Collection is a collection of sets.
//
// its resulting values is a union or intersection of all the sets, depending on the operator.
type Collection struct {
	subsets  []Uniq
	operator string
}

// NewCollection creates a new collection.
func NewCollection(operator string) *Collection {
	return &Collection{
		subsets:  []Uniq{},
		operator: operator,
	}
}

// Add adds the elements into a new subset in the collection.
func (u *Collection) Add(elements []string) {
	subset := Uniq{}
	subset.Add(elements...)
	u.subsets = append(u.subsets, subset)
}

// Values flattens the subsets using the operator, and returns the collection as a slice of strings.
func (u *Collection) Values() []string {
	if len(u.subsets) == 0 {
		return []string{}
	}
	subset := u.subsets[0]
	for i := 1; i < len(u.subsets); i++ {
		if strings.EqualFold(u.operator, "and") {
			subset = subset.Intersect(u.subsets[i])
		} else {
			subset = subset.Union(u.subsets[i])
		}
	}
	return subset.Values()
}
