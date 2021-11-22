// Copyright 2020 The gVisor Authors.
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

// Package checklocks performs lock analysis to identify and flag unprotected
// access to annotated fields.
//
// For detailed usage refer to README.md in the same directory.
package checklocks

import (
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"time"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

const Benchmark = true

// Analyzer is the main entrypoint.
var Analyzer = &analysis.Analyzer{
	Name:       "checklocks",
	Doc:        "checks lock preconditions on functions and fields",
	Run:        run,
	Requires:   []*analysis.Analyzer{buildssa.Analyzer},
	FactTypes:  []analysis.Fact{(*atomicAlignment)(nil), (*lockFieldFacts)(nil), (*lockGuardFacts)(nil), (*lockFunctionFacts)(nil)},
	ResultType: reflect.TypeOf((*PkgPerfData)(nil)),
}

// PKfPerfData stores revelant analysis stats for processing in benchlocks.
type PkgPerfData struct {
	// ErrorSiteCount records the total number of errors reported at a token.Pos.
	ErrorSiteCount map[token.Pos]int

	// BasicBlocksVisits stores the average number of visits made per basic block
	// in the control flow graph of a function.
	BasicBlockVisits map[string]int

	// FunctionCheckTime is the time spent analyzing a function. The data
	// is saved as time.Duration as the unit of time can be decided after processing.
	FunctionCheckTime map[string]time.Duration
}

// passContext is a pass with additional expected failures.
type passContext struct {
	pass       *analysis.Pass
	failures   map[positionKey]*failData
	exemptions map[positionKey]struct{}
	forced     map[positionKey]struct{}
	functions  map[*ssa.Function]struct{}
	perf       *PkgPerfData
	inferMode  bool
}

// forAllTypes applies the given function over all types.
func (pc *passContext) forAllTypes(fn func(ts *ast.TypeSpec)) {
	for _, f := range pc.pass.Files {
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.GenDecl)
			if !ok || d.Tok != token.TYPE {
				continue
			}
			for _, gs := range d.Specs {
				fn(gs.(*ast.TypeSpec))
			}
		}
	}
}

// forAllFunctions applies the given function over all functions.
func (pc *passContext) forAllFunctions(fn func(fn *ast.FuncDecl)) {
	for _, f := range pc.pass.Files {
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			fn(d)
		}
	}
}

// run is the main entrypoint.
func run(pass *analysis.Pass) (interface{}, error) {
	pc := &passContext{
		pass:       pass,
		failures:   make(map[positionKey]*failData),
		exemptions: make(map[positionKey]struct{}),
		forced:     make(map[positionKey]struct{}),
		functions:  make(map[*ssa.Function]struct{}),
		perf:       nil,
	}
	if Benchmark {
		pc.perf = &PkgPerfData{
			ErrorSiteCount:    make(map[token.Pos]int),
			BasicBlockVisits:  make(map[string]int),
			FunctionCheckTime: make(map[string]time.Duration),
		}
	}

	// Find all line failure annotations.
	pc.extractLineFailures()

	// Find all struct declarations and export relevant facts.
	pc.forAllTypes(func(ts *ast.TypeSpec) {
		if ss, ok := ts.Type.(*ast.StructType); ok {
			pc.exportLockFieldFacts(ts, ss)
		}
	})
	pc.forAllTypes(func(ts *ast.TypeSpec) {
		if ss, ok := ts.Type.(*ast.StructType); ok {
			pc.exportHatGuards(ts, ss)
		}
	})
	pc.forAllTypes(func(ts *ast.TypeSpec) {
		if ss, ok := ts.Type.(*ast.StructType); ok {
			pc.exportLockGuardFacts(ts, ss)
		}
	})
	// Check all alignments.
	pc.forAllTypes(func(ts *ast.TypeSpec) {
		typ, ok := pass.TypesInfo.TypeOf(ts.Name).(*types.Named)
		if !ok {
			return
		}
		pc.checkTypeAlignment(pass.Pkg, typ)
	})

	// Find all function declarations and export relevant facts.
	pc.forAllFunctions(func(fn *ast.FuncDecl) {
		pc.exportFunctionFacts(fn)
	})

	// Find all function declarations and export relevant facts.
	pc.forAllFunctions(func(fn *ast.FuncDecl) {
		pc.gatherInferredParams(fn)
	})

	// Scan all code looking for invalid accesses.
	state := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	callgraph := static.CallGraph(state.Pkg.Prog)
	ssautil.MainPackages()

	for _, fn := range state.SrcFuncs {
		// Import function facts generated above.
		//
		// Note that anonymous(closures) functions do not have an
		// object but do show up in the SSA. They can only be invoked
		// by named functions in the package, and they are analyzing
		// inline on every call. Thus we skip the analysis here. They
		// will be hit on calls, or picked up in the pass below.
		if obj := fn.Object(); obj == nil {
			continue
		}
		var lff lockFunctionFacts
		pc.pass.ImportObjectFact(fn.Object(), &lff)

		// Do we ignore this?
		if lff.Ignore {
			continue
		}

		var start time.Time
		if pc.perf != nil {
			start = time.Now()
		}

		// Check the basic blocks in the function.
		pc.checkFunction(nil, fn, &lff, nil, false /* force */)

		if pc.perf != nil {
			pc.perf.FunctionCheckTime[fn.Name()] = time.Since(start)
		}
	}
	for _, fn := range state.SrcFuncs {
		// Ensure all anonymous functions are hit. They are not
		// permitted to have any lock preconditions.
		if obj := fn.Object(); obj != nil {
			continue
		}
		var nolff lockFunctionFacts
		pc.checkFunction(nil, fn, &nolff, nil, false /* force */)
	}

	// Check for expected failures.
	pc.checkFailures()

	return pc.perf, nil
}
