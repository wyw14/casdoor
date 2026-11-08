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

package auditsnapshot

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// SnapshotFilter is the complete, explicit description of the record selection.
// It maps 1:1 to parameterized SQL on the producer side:
//
//	organization = Organization
//	[AND action = Action]
//	[AND created_time >= CreatedTimeFrom]
//	[AND created_time <  CreatedTimeTo]
//	ORDER BY id ASC LIMIT MaxRecords
//
// CreatedTimeFrom is inclusive and CreatedTimeTo is exclusive. The selection
// is finite: MaxRecords is mandatory and bounded. Field order is part of the
// signed format.
type SnapshotFilter struct {
	Organization    string `json:"organization"`
	Action          string `json:"action,omitempty"`
	CreatedTimeFrom string `json:"createdTimeFrom,omitempty"`
	CreatedTimeTo   string `json:"createdTimeTo,omitempty"`
	MaxRecords      int    `json:"maxRecords"`
}

// Validate checks that the filter selects a finite set inside exactly one
// organization.
func (f SnapshotFilter) Validate() error {
	if f.Organization == "" {
		return errors.New("snapshot filter: organization is required")
	}
	if f.MaxRecords <= 0 {
		return errors.New("snapshot filter: maxRecords must be positive")
	}
	if f.MaxRecords > MaxRecordsHardLimit {
		return fmt.Errorf("snapshot filter: maxRecords exceeds the hard limit of %d", MaxRecordsHardLimit)
	}
	if f.CreatedTimeFrom != "" && f.CreatedTimeTo != "" && f.CreatedTimeFrom > f.CreatedTimeTo {
		return errors.New("snapshot filter: createdTimeFrom is after createdTimeTo")
	}
	return nil
}

// Digest commits the conditions (including the limit) so a verifier can detect
// a tampered or substituted filter.
func (f SnapshotFilter) Digest() (string, error) {
	b, err := canonicalJSON(f)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(domainSeparatedSum(FilterFormatVersion, b)), nil
}
