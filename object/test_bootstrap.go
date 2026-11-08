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

// InitForTest boots the ORM from an already loaded beego configuration for in-process
// tests of other packages. It only flips the database-creation flag, which is reserved
// for external database servers, and then runs the regular adapter and table setup.
func InitForTest() {
	createDatabase = false
	InitAdapter()
	CreateTables()
}

// CloseForTest releases the database engine opened by InitForTest.
func CloseForTest() {
	if ormer != nil && ormer.Engine != nil {
		_ = ormer.Engine.Close()
	}
}
