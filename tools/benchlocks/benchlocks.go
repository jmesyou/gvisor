package benchlocks

import (
	"fmt"
	"time"

	"golang.org/x/tools/go/analysis"
	"gvisor.dev/gvisor/tools/checklocks"
)

type Stats map[string]string

type StatsPass struct {
	pass *analysis.Pass
}

var Analyzer = &analysis.Analyzer{
	Name:      "benchlocks",
	Doc:       "Processes and outputs stats from the checklocks analyzer",
	Run:       run,
	Requires:  []*analysis.Analyzer{checklocks.Analyzer},
	FactTypes: []analysis.Fact{},
}

func (sp *StatsPass) collectChecklocksStats(pgf *checklocks.PkgPerfFacts) Stats {
	var (
		total   time.Duration
		fn      string
		slowest time.Duration
	)
	for f, time := range pgf.FunctionCheckTime {
		total += time
		if time > slowest {
			fn, slowest = f, time
		}
	}
	stats := make(map[string]string)
	stats["total_time"] = fmt.Sprintf("%d ms", total.Milliseconds())
	stats["slowest_function"] = fn
	stats["slowest_time"] = fmt.Sprintf("%d us", total.Microseconds())

	var totalErrors int
	problematicFiles := make(map[string]struct{})
	for pos, count := range pgf.ErrorSiteCount {
		position := sp.pass.Fset.Position(pos)
		problematicFiles[position.Filename] = struct{}{}
		totalErrors += count
	}

	stats["error_files"] = fmt.Sprint(problematicFiles)
	stats["total_errors"] = fmt.Sprint(totalErrors)

	return stats
}

func run(pass *analysis.Pass) (interface{}, error) {
	if !checklocks.Benchmark {
		return nil, nil
	}

	sp := StatsPass{pass}

	results := sp.pass.ResultOf[checklocks.Analyzer].(*checklocks.PkgPerfFacts)
	stats := sp.collectChecklocksStats(results)

	for name, data := range stats {
		pass.Report(analysis.Diagnostic{
			Message: fmt.Sprintf("%s-%s=%s", pass.Pkg.Name(), name, data),
		})
	}

	return nil, nil
}
