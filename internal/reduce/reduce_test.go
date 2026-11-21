package reduce

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tellagen/tellagen-proxy/protocol"
)

var t0 = time.Date(2026, 11, 4, 13, 0, 0, 0, time.UTC)

func line(count int, step time.Duration, value func(i int) float64) []Point {
	points := make([]Point, 0, count)
	for i := range count {
		points = append(points, Point{At: t0.Add(time.Duration(i) * step), Value: value(i)})
	}
	return points
}

func TestMatrixKeepsPointsAndComputesStats(t *testing.T) {
	data, truncated := Matrix([]InputSeries{{
		Labels: map[string]string{"service": "checkout"},
		Points: []Point{{t0, 38}, {t0.Add(30 * time.Second), 100}, {t0.Add(60 * time.Second), 40}},
	}}, 30, protocol.Limits{MaxPoints: 500, MaxSeries: 20})
	if truncated {
		t.Error("truncated")
	}
	if data.Kind != protocol.DataMatrix || data.SeriesTotal != 1 || len(data.Series) != 1 || data.DownsampledFromPoints != 0 {
		t.Fatalf("data = %+v", data)
	}
	series := data.Series[0]
	if series.StepS != 30 || !series.Start.Equal(t0) || len(series.Values) != 3 || *series.Values[1] != 100 {
		t.Errorf("series = %+v", series)
	}
	want := protocol.SeriesStats{Min: 38, Max: 100, Avg: 178.0 / 3, First: 38, Last: 40, MaxAt: t0.Add(30 * time.Second)}
	if *series.Stats != want {
		t.Errorf("stats = %+v, want %+v", *series.Stats, want)
	}
}

func TestMatrixGapIsNilAndNotANumberIsAGap(t *testing.T) {
	data, _ := Matrix([]InputSeries{{Points: []Point{
		{t0, 1},
		{t0.Add(30 * time.Second), math.NaN()},
		{t0.Add(90 * time.Second), 3},
		{t0.Add(120 * time.Second), math.Inf(1)},
	}}}, 30, protocol.Limits{MaxPoints: 500})
	values := data.Series[0].Values
	if len(values) != 4 || *values[0] != 1 || values[1] != nil || values[2] != nil || *values[3] != 3 {
		t.Fatalf("values = %v", values)
	}
	if data.Series[0].Stats.Max != 3 {
		t.Errorf("stats = %+v", data.Series[0].Stats)
	}
	if _, err := json.Marshal(data); err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
}

func TestMatrixDownsamplesToThePointLimitAndKeepsThePeak(t *testing.T) {
	const samples = 2880
	data, _ := Matrix([]InputSeries{{Points: line(samples, 30*time.Second, func(i int) float64 {
		if i == 1711 {
			return 1000
		}
		return 1
	})}}, 30, protocol.Limits{MaxPoints: 500})
	series := data.Series[0]
	if len(series.Values) > 500 {
		t.Fatalf("len(values) = %d", len(series.Values))
	}
	if data.DownsampledFromPoints != samples {
		t.Errorf("DownsampledFromPoints = %d", data.DownsampledFromPoints)
	}
	if series.StepS != 180 {
		t.Errorf("StepS = %d", series.StepS)
	}
	peakSeen := false
	for _, value := range series.Values {
		if value != nil && *value == 1000 {
			peakSeen = true
		}
	}
	if !peakSeen {
		t.Error("the downsampled line lost its peak")
	}
	if series.Stats.Max != 1000 || !series.Stats.MaxAt.Equal(t0.Add(1711*30*time.Second)) {
		t.Errorf("stats = %+v", series.Stats)
	}
}

func TestMatrixPointLimitDefaultsToTheCeiling(t *testing.T) {
	data, _ := Matrix([]InputSeries{{Points: line(1000, time.Second, func(int) float64 { return 1 })}}, 1, protocol.Limits{})
	if got := len(data.Series[0].Values); got > maxPointsCeiling {
		t.Fatalf("len(values) = %d", got)
	}
}

func TestMatrixDoesNotAllocateForAHostileGrid(t *testing.T) {
	data, _ := Matrix([]InputSeries{{Points: []Point{
		{t0, 1},
		{t0.Add(time.Second), 2},
		{t0.Add(10 * 365 * 24 * time.Hour), 3},
	}}}, 1, protocol.Limits{MaxPoints: 100})
	if got := len(data.Series[0].Values); got > 100 {
		t.Fatalf("len(values) = %d", got)
	}
}

func TestMatrixKeepsTheHighestSeries(t *testing.T) {
	input := make([]InputSeries, 0, 30)
	for i := range 30 {
		input = append(input, InputSeries{
			Labels: map[string]string{"pod": fmt.Sprintf("p%02d", i)},
			Points: []Point{{t0, float64(i)}},
		})
	}
	data, truncated := Matrix(input, 30, protocol.Limits{MaxSeries: 3})
	if !truncated || data.SeriesTotal != 30 || len(data.Series) != 3 {
		t.Fatalf("truncated %v, data %+v", truncated, data)
	}
	for i, want := range []string{"p29", "p28", "p27"} {
		if got := data.Series[i].Labels["pod"]; got != want {
			t.Errorf("series %d = %s, want %s", i, got, want)
		}
	}
}

func TestMatrixEmptyAndAllGaps(t *testing.T) {
	data, truncated := Matrix(nil, 30, protocol.Limits{})
	if truncated || data.SeriesTotal != 0 || len(data.Series) != 0 {
		t.Fatalf("data = %+v", data)
	}
	data, _ = Matrix([]InputSeries{{Labels: map[string]string{"a": "b"}, Points: []Point{{t0, math.NaN()}}}}, 30, protocol.Limits{})
	if data.Series[0].Stats != nil || data.Series[0].Values[0] != nil {
		t.Fatalf("series = %+v", data.Series[0])
	}
}

func TestVector(t *testing.T) {
	data, truncated := Vector([]protocol.Sample{
		{Labels: map[string]string{"a": "1"}, Value: 1, At: t0},
		{Labels: map[string]string{"a": "2"}, Value: math.NaN(), At: t0},
		{Labels: map[string]string{"a": "3"}, Value: 3, At: t0},
		{Labels: map[string]string{"a": "4"}, Value: 2, At: t0},
	}, protocol.Limits{MaxSeries: 2})
	if !truncated || data.Kind != protocol.DataVector || data.SeriesTotal != 4 || len(data.Samples) != 2 {
		t.Fatalf("truncated %v, data %+v", truncated, data)
	}
	if data.Samples[0].Value != 3 || data.Samples[1].Value != 2 {
		t.Errorf("samples = %+v", data.Samples)
	}
}

func TestPatterns(t *testing.T) {
	data, truncated := Patterns([]protocol.LogPattern{{Pattern: "a", Count: 1}, {Pattern: "b", Count: 9}, {Pattern: "c", Count: 5}}, protocol.Limits{MaxPatterns: 2})
	if !truncated || len(data.Patterns) != 2 || data.Patterns[0].Pattern != "b" || data.Patterns[1].Pattern != "c" {
		t.Fatalf("truncated %v, data %+v", truncated, data)
	}
}

func TestNormalizePatterns(t *testing.T) {
	data := &protocol.ResultData{Patterns: []protocol.LogPattern{
		{Pattern: `connection <_> to <host> failed after 30.5 s id 550e8400-e29b-41d4-a716-446655440000 trace 4bf92f3577b34da6 code [redacted:ip] v2`},
	}}
	NormalizePatterns(data)
	want := `connection <_> to <_> failed after <_> s id <_> trace <_> code [redacted:ip] v2`
	if got := data.Patterns[0].Pattern; got != want {
		t.Errorf("Pattern = %q, want %q", got, want)
	}
}

func TestCutLines(t *testing.T) {
	data := &protocol.ResultData{Lines: []protocol.LogLine{{Text: strings.Repeat("ä", 600)}, {Text: "short"}, {Text: "bad\xff" + strings.Repeat("a", 600)}}}
	if !CutLines(data, 500) {
		t.Error("CutLines() = false")
	}
	if got := len([]rune(data.Lines[0].Text)); got != 500 {
		t.Errorf("first line has %d characters", got)
	}
	if data.Lines[1].Text != "short" {
		t.Errorf("short line = %q", data.Lines[1].Text)
	}
	encoded, err := json.Marshal(data)
	if err != nil || !json.Valid(encoded) {
		t.Fatalf("Marshal() = %v", err)
	}
	if CutLines(&protocol.ResultData{Lines: []protocol.LogLine{{Text: "short"}}}, 500) {
		t.Error("CutLines() = true with nothing to cut")
	}
	if CutLines(data, 0) {
		t.Error("CutLines() = true with no limit")
	}
}

func TestNamesAndItems(t *testing.T) {
	data, truncated := Names([]string{"a", "b", "c"}, protocol.Limits{MaxItems: 2})
	if !truncated || len(data.Names) != 2 || data.Kind != protocol.DataNames {
		t.Fatalf("truncated %v, data %+v", truncated, data)
	}
	items, truncated := Items([]int{1, 2}, protocol.Limits{MaxItems: 2})
	if truncated || len(items) != 2 {
		t.Fatalf("items %v, truncated %v", items, truncated)
	}
	items, truncated = Items([]int{1, 2}, protocol.Limits{})
	if truncated || len(items) != 2 {
		t.Fatalf("items %v, truncated %v", items, truncated)
	}
}

func TestFit(t *testing.T) {
	builders := map[string]func(n int) *protocol.ResultData{
		"series": func(n int) *protocol.ResultData {
			data := &protocol.ResultData{}
			for i := range n {
				data.Series = append(data.Series, protocol.Series{Labels: map[string]string{"p": fmt.Sprint(i)}, Start: t0})
			}
			return data
		},
		"samples": func(n int) *protocol.ResultData {
			return &protocol.ResultData{Samples: make([]protocol.Sample, n)}
		},
		"lines": func(n int) *protocol.ResultData {
			return &protocol.ResultData{Lines: make([]protocol.LogLine, n)}
		},
		"patterns": func(n int) *protocol.ResultData {
			return &protocol.ResultData{Patterns: make([]protocol.LogPattern, n)}
		},
		"names": func(n int) *protocol.ResultData {
			return &protocol.ResultData{Names: make([]string, n)}
		},
		"datasources": func(n int) *protocol.ResultData {
			return &protocol.ResultData{Datasources: make([]protocol.Datasource, n)}
		},
		"dashboards": func(n int) *protocol.ResultData {
			return &protocol.ResultData{Dashboards: make([]protocol.Dashboard, n)}
		},
		"panel queries": func(n int) *protocol.ResultData {
			return &protocol.ResultData{PanelQueries: make([]protocol.PanelQuery, n)}
		},
		"alert rules": func(n int) *protocol.ResultData {
			return &protocol.ResultData{AlertRules: make([]protocol.AlertRule, n)}
		},
		"alert rule versions": func(n int) *protocol.ResultData {
			return &protocol.ResultData{AlertRuleVersions: make([]protocol.AlertRuleVersion, n)}
		},
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			data := build(2000)
			full, truncated, err := Fit(data, 0)
			if err != nil || truncated {
				t.Fatalf("measure: %v %v", truncated, err)
			}
			if full < 2000 {
				t.Fatalf("full size = %d", full)
			}
			size, truncated, err := Fit(data, 1000)
			if err != nil {
				t.Fatalf("Fit() error = %v", err)
			}
			if !truncated || size > 1000 {
				t.Fatalf("size %d, truncated %v", size, truncated)
			}
		})
	}
}

func TestFitNothingLeftToDrop(t *testing.T) {
	data := &protocol.ResultData{Kind: protocol.DataNames}
	size, truncated, err := Fit(data, 1)
	if err != nil || truncated || size == 0 {
		t.Fatalf("size %d, truncated %v, err %v", size, truncated, err)
	}
}

func TestCutLabelsCutsValuesAfterRedaction(t *testing.T) {
	long := strings.Repeat("a", 10)
	data := &protocol.ResultData{
		Series:  []protocol.Series{{Labels: map[string]string{"msg": long, "pod": "p1"}}},
		Samples: []protocol.Sample{{Labels: map[string]string{"msg": strings.Repeat("õ", 10)}}},
	}
	if !CutLabels(data, 4) {
		t.Fatal("CutLabels() = false")
	}
	if got := data.Series[0].Labels; got["msg"] != "aaaa" || got["pod"] != "p1" {
		t.Errorf("series labels = %v", got)
	}
	if got := data.Samples[0].Labels["msg"]; got != "õõõõ" {
		t.Errorf("sample label = %q", got)
	}
	if CutLabels(data, 4) {
		t.Error("a second cut reported a change")
	}
	if CutLabels(&protocol.ResultData{Series: []protocol.Series{{Labels: map[string]string{"msg": long}}}}, 0) {
		t.Error("a limit of zero cut a value")
	}
}
