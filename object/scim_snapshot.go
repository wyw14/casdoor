// Copyright 2026 The Casdoor Authors. All Rights Reserved.
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

package object

import (
	"fmt"

	"github.com/xorm-io/builder"
)

// The SCIM snapshot extension may only sort by columns that exist on the table,
// so a client supplied sortBy can never reach the ORDER BY clause as raw SQL.
var allowedScimUserSnapshotSortColumns = map[string]struct{}{
	"name":         {},
	"display_name": {},
	"external_id":  {},
	"type":         {},
	"homepage":     {},
	"first_name":   {},
	"last_name":    {},
	"email":        {},
	"phone":        {},
	"avatar":       {},
	"location":     {},
	"region":       {},
	"country_code": {},
	"owner":        {},
	"created_time": {},
	"updated_time": {},
}

var allowedScimGroupSnapshotSortColumns = map[string]struct{}{
	"display_name": {},
	"owner":        {},
	"created_time": {},
	"updated_time": {},
}

func scimSnapshotOrderBy(allowed map[string]struct{}, sortColumn, tieBreaker string, descending bool) (string, error) {
	if _, ok := allowed[sortColumn]; !ok {
		return "", fmt.Errorf("the SCIM snapshot sort column: %s is not allowed", sortColumn)
	}
	direction := "ASC"
	if descending {
		direction = "DESC"
	}
	// The NOT NULL primary key tie-breaker makes the order total: rows with equal
	// sort values, including NULLs, keep a stable position across the pages.
	return fmt.Sprintf("%s %s, %s ASC", quoteColumn(sortColumn), direction, quoteColumn(tieBreaker)), nil
}

// scopedSnapshotCond folds the organization bound into the filter condition. Folding
// it into the cond (instead of mutating the shared tx session twice) keeps the count
// and the find identical regardless of xorm's per-statement condition reset.
func scopedSnapshotCond(owner string, cond builder.Cond) builder.Cond {
	if owner == "" {
		return cond
	}
	return builder.And(cond, builder.Eq{"owner": owner})
}

// GetScimSnapshotUsers returns the total count and every matching user in a single
// read transaction, so the count, the ordering and the rendered values all share one
// point in time. The transaction ends before the caller seals the snapshot artifact.
func GetScimSnapshotUsers(owner string, cond builder.Cond, sortColumn string, descending bool) (int64, []*User, error) {
	orderBy, err := scimSnapshotOrderBy(allowedScimUserSnapshotSortColumns, sortColumn, "id", descending)
	if err != nil {
		return 0, nil, err
	}
	scopedCond := scopedSnapshotCond(owner, cond)

	session := ormer.Engine.NewSession()
	defer session.Close()
	if err = session.Begin(); err != nil {
		return 0, nil, err
	}
	defer func() { _ = session.Rollback() }()

	count, err := session.Where(scopedCond).Count(&User{})
	if err != nil {
		return 0, nil, err
	}

	users := make([]*User, 0, count)
	if err = session.Where(scopedCond).OrderBy(orderBy).Find(&users); err != nil {
		return 0, nil, err
	}

	if err = session.Commit(); err != nil {
		return 0, nil, err
	}
	return count, users, nil
}

// GetScimSnapshotGroups is the group counterpart of GetScimSnapshotUsers, with the
// (owner, name) primary key as the immutable unique tie-breaker.
func GetScimSnapshotGroups(owner string, cond builder.Cond, sortColumn string, descending bool) (int64, []*Group, error) {
	orderBy, err := scimSnapshotOrderBy(allowedScimGroupSnapshotSortColumns, sortColumn, "name", descending)
	if err != nil {
		return 0, nil, err
	}
	scopedCond := scopedSnapshotCond(owner, cond)

	session := ormer.Engine.NewSession()
	defer session.Close()
	if err = session.Begin(); err != nil {
		return 0, nil, err
	}
	defer func() { _ = session.Rollback() }()

	count, err := session.Where(scopedCond).Count(&Group{})
	if err != nil {
		return 0, nil, err
	}

	groups := make([]*Group, 0, count)
	if err = session.Where(scopedCond).OrderBy(orderBy).Find(&groups); err != nil {
		return 0, nil, err
	}

	if err = session.Commit(); err != nil {
		return 0, nil, err
	}
	return count, groups, nil
}
