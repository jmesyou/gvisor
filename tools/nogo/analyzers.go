// Copyright 2019 The gVisor Authors.
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

package nogo

import (
	"encoding/gob"

	"golang.org/x/tools/go/analysis"
	"honnef.co/go/tools/staticcheck"
	"honnef.co/go/tools/stylecheck"

	"gvisor.dev/gvisor/tools/benchlocks"
)

// AllAnalyzers is a list of all available analyzers.
var AllAnalyzers = []*analysis.Analyzer{
	benchlocks.Analyzer,
}

func register(all []*analysis.Analyzer) {
	// Register all fact types.
	//
	// N.B. This needs to be done recursively, because there may be
	// analyzers in the Requires list that do not appear explicitly above.
	registered := make(map[*analysis.Analyzer]struct{})
	var registerOne func(*analysis.Analyzer)
	registerOne = func(a *analysis.Analyzer) {
		if _, ok := registered[a]; ok {
			return
		}

		// Register dependencies.
		for _, da := range a.Requires {
			registerOne(da)
		}

		// Register local facts.
		for _, f := range a.FactTypes {
			gob.Register(f)
		}

		registered[a] = struct{}{} // Done.
	}
	for _, a := range all {
		registerOne(a)
	}
}

func init() {
	// Add all staticcheck analyzers.
	for _, a := range staticcheck.Analyzers {
		AllAnalyzers = append(AllAnalyzers, a)
	}
	// Add all stylecheck analyzers.
	for _, a := range stylecheck.Analyzers {
		AllAnalyzers = append(AllAnalyzers, a)
	}

	// Register lists.
	register(AllAnalyzers)
}
