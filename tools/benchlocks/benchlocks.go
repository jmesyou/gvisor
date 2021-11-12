// Package benchlocks processes collected data from the checklocks
// analyzer and outputs statistics as diagnostics.
package benchlocks

import (
	"fmt"
	"time"

	"golang.org/x/tools/go/analysis"
	"gvisor.dev/gvisor/tools/checklocks"
)

type Stats map[string]string

type statsPass struct {
	pass *analysis.Pass
}

var Analyzer = &analysis.Analyzer{
	Name:     "benchlocks",
	Doc:      "Processes and outputs stats from the checklocks analyzer",
	Run:      run,
	Requires: []*analysis.Analyzer{checklocks.Analyzer},
}

func (sp *statsPass) collectChecklocksStats(ppd *checklocks.PkgPerfData) Stats {
	var (
		total   time.Duration
		slowest string
		max     time.Duration
	)
	for f, time := range ppd.FunctionCheckTime {
		total += time
		if time > max {
			slowest, max = f, time
		}
	}
	stats := make(map[string]string)
	stats["total_time"] = fmt.Sprintf("%d ms", total.Milliseconds())
	stats["slowest_function"] = slowest
	stats["slowest_time"] = fmt.Sprintf("%d us", max.Microseconds())

	var totalErrors int
	problematicFiles := make(map[string]struct{})
	for pos, count := range ppd.ErrorSiteCount {
		position := sp.pass.Fset.Position(pos)
		problematicFiles[position.Filename] = struct{}{}
		totalErrors += count
	}

	stats["error_files"] = fmt.Sprint(problematicFiles)
	stats["total_errors"] = fmt.Sprint(totalErrors)

	return stats
}

func run(pass *analysis.Pass) (interface{}, error) {
	sp := statsPass{pass}
	ppd := sp.pass.ResultOf[checklocks.Analyzer].(*checklocks.PkgPerfData)

	if checklocks.Benchmark && ppd == nil {
		return nil, nil
	}

	stats := sp.collectChecklocksStats(ppd)

	for name, data := range stats {
		pass.Report(analysis.Diagnostic{
			Message: fmt.Sprintf("%s-%s=%s", pass.Pkg.Name(), name, data),
		})
	}

	return nil, nil
}
