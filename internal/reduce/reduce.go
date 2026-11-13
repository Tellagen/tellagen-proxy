// Package reduce turns what Grafana returned into the small result that leaves the
// network: named fields only, bounded series and points. Redact before CutLines
// and Fit, so a secret is never cut in half before redaction sees it.
package reduce

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tellagen/tellagen-proxy/protocol"
)

// maxPointsCeiling is the trend block's maximum, used when no limit is set.
const maxPointsCeiling = 500

// MaxLabelCharsWithoutLogLines bounds a value of a series label of a Loki query
// while log lines are off. A real label fits, and a whole line does not.
const MaxLabelCharsWithoutLogLines = 128

// Point is one sample of a series.
type Point struct {
	At    time.Time
	Value float64
}

// InputSeries is one series as the source returned it.
type InputSeries struct {
	Labels map[string]string
	Points []Point
}

// Matrix reduces a range result. It keeps the series with the highest peaks, puts
// the points on a regular grid with a gap as nil, and downsamples to the point
// limit. A bucket keeps its highest value, so a downsampled line still shows the
// peak. The stats cover every point. truncated reports dropped series.
func Matrix(input []InputSeries, stepS int, limits protocol.Limits) (data *protocol.ResultData, truncated bool) {
	entries, spacing := measure(input)
	data = &protocol.ResultData{Kind: protocol.DataMatrix, SeriesTotal: len(input), Series: []protocol.Series{}}
	if limits.MaxSeries > 0 && len(entries) > limits.MaxSeries {
		entries = entries[:limits.MaxSeries]
		truncated = true
	}
	first, last, samples := span(entries)

	// Grafana can widen the step that was asked for, so the samples decide.
	step := max(time.Duration(stepS)*time.Second, spacing, time.Second).Truncate(time.Second)
	maxPoints := limits.MaxPoints
	if maxPoints <= 0 {
		maxPoints = maxPointsCeiling
	}
	gridPoints := 1
	if !first.IsZero() {
		gridPoints = int(last.Sub(first)/step) + 1
	}
	factor := (gridPoints + maxPoints - 1) / maxPoints
	bucket := step * time.Duration(factor)
	bucketCount := (gridPoints-1)/factor + 1

	for _, entry := range entries {
		values := make([]*float64, bucketCount)
		for _, point := range entry.series.Points {
			index := int(point.At.Sub(first) / bucket)
			if index >= bucketCount {
				index = bucketCount - 1
			}
			if values[index] == nil || point.Value > *values[index] {
				value := point.Value
				values[index] = &value
			}
		}
		data.Series = append(data.Series, protocol.Series{
			Labels: entry.series.Labels,
			Start:  first.UTC(),
			StepS:  int(bucket / time.Second),
			Values: values,
			Stats:  entry.stats,
		})
	}
	if factor > 1 {
		data.DownsampledFromPoints = samples
	}
	return data, truncated
}

// measuredSeries is a series with its points sorted and finite, and its stats.
type measuredSeries struct {
	series InputSeries
	stats  *protocol.SeriesStats
}

// measure sorts the points of every series, drops the ones that are not numbers,
// and orders the series by peak, highest first. It also returns the smallest gap
// between two points, which is the real step of the data.
func measure(input []InputSeries) ([]measuredSeries, time.Duration) {
	entries := make([]measuredSeries, 0, len(input))
	spacing := time.Duration(0)
	for _, series := range input {
		points := slices.Clone(series.Points)
		slices.SortStableFunc(points, func(a, b Point) int { return a.At.Compare(b.At) })
		for i := 1; i < len(points); i++ {
			if delta := points[i].At.Sub(points[i-1].At); delta > 0 && (spacing == 0 || delta < spacing) {
				spacing = delta
			}
		}
		series.Points = finitePoints(points)
		entries = append(entries, measuredSeries{series, seriesStats(series.Points)})
	}
	slices.SortStableFunc(entries, func(a, b measuredSeries) int {
		if order := cmp.Compare(peak(b.stats), peak(a.stats)); order != 0 {
			return order
		}
		return cmp.Compare(labelKey(a.series.Labels), labelKey(b.series.Labels))
	})
	return entries, spacing
}

// span returns the first and last time of the series and the most points any of
// them has.
func span(entries []measuredSeries) (first, last time.Time, samples int) {
	for _, entry := range entries {
		points := entry.series.Points
		samples = max(samples, len(points))
		if len(points) == 0 {
			continue
		}
		if first.IsZero() || points[0].At.Before(first) {
			first = points[0].At
		}
		if end := points[len(points)-1].At; end.After(last) {
			last = end
		}
	}
	return first, last, samples
}

func finitePoints(points []Point) []Point {
	return slices.DeleteFunc(points, func(point Point) bool { return !isFinite(point.Value) })
}

func isFinite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

func peak(stats *protocol.SeriesStats) float64 {
	if stats == nil {
		return math.Inf(-1)
	}
	return stats.Max
}

func seriesStats(points []Point) *protocol.SeriesStats {
	if len(points) == 0 {
		return nil
	}
	stats := &protocol.SeriesStats{
		Min: points[0].Value, Max: points[0].Value, First: points[0].Value, Last: points[len(points)-1].Value,
		MaxAt: points[0].At.UTC(),
	}
	sum := 0.0
	for _, point := range points {
		sum += point.Value
		stats.Min = min(stats.Min, point.Value)
		if point.Value > stats.Max {
			stats.Max = point.Value
			stats.MaxAt = point.At.UTC()
		}
	}
	stats.Avg = sum / float64(len(points))
	return stats
}

func labelKey(labels map[string]string) string {
	keys := slices.Sorted(maps.Keys(labels))
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(labels[key])
		b.WriteByte(0)
	}
	return b.String()
}

// Vector reduces an instant result. A value that is not a number cannot travel as
// JSON and is left out.
func Vector(input []protocol.Sample, limits protocol.Limits) (data *protocol.ResultData, truncated bool) {
	samples := slices.DeleteFunc(slices.Clone(input), func(sample protocol.Sample) bool { return !isFinite(sample.Value) })
	slices.SortStableFunc(samples, func(a, b protocol.Sample) int {
		if order := cmp.Compare(b.Value, a.Value); order != 0 {
			return order
		}
		return cmp.Compare(labelKey(a.Labels), labelKey(b.Labels))
	})
	if limits.MaxSeries > 0 && len(samples) > limits.MaxSeries {
		samples = samples[:limits.MaxSeries]
		truncated = true
	}
	return &protocol.ResultData{Kind: protocol.DataVector, SeriesTotal: len(input), Samples: samples}, truncated
}

// Patterns reduces Loki patterns to the most frequent ones.
func Patterns(input []protocol.LogPattern, limits protocol.Limits) (data *protocol.ResultData, truncated bool) {
	patterns := slices.Clone(input)
	slices.SortStableFunc(patterns, func(a, b protocol.LogPattern) int { return cmp.Compare(b.Count, a.Count) })
	if limits.MaxPatterns > 0 && len(patterns) > limits.MaxPatterns {
		patterns = patterns[:limits.MaxPatterns]
		truncated = true
	}
	return &protocol.ResultData{Kind: protocol.DataPatterns, Patterns: patterns}, truncated
}

var patternVariables = []*regexp.Regexp{
	regexp.MustCompile(`<[A-Za-z_][A-Za-z0-9_]*>`),
	regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`),
	regexp.MustCompile(`\b[0-9a-fA-F]*[0-9][0-9a-fA-F]{7,}\b`),
	regexp.MustCompile(`\b\d+(?:\.\d+)?\b`),
}

// NormalizePatterns replaces what a pattern still holds as a value with <_>: a
// named variable, a UUID, a long hex id or a number. It runs after redaction, so
// that an address is one placeholder and not four numbers.
func NormalizePatterns(data *protocol.ResultData) {
	for i := range data.Patterns {
		pattern := data.Patterns[i].Pattern
		for _, variable := range patternVariables {
			pattern = variable.ReplaceAllString(pattern, "<_>")
		}
		data.Patterns[i].Pattern = pattern
	}
}

// CutLines cuts each log line to maxChars characters and reports whether it cut
// one. It runs after redaction, because a cut secret no longer matches a rule.
func CutLines(data *protocol.ResultData, maxChars int) bool {
	if maxChars <= 0 {
		return false
	}
	cut := false
	for i := range data.Lines {
		text := data.Lines[i].Text
		if utf8.RuneCountInString(text) <= maxChars {
			continue
		}
		data.Lines[i].Text = string([]rune(strings.ToValidUTF8(text, "�"))[:maxChars])
		cut = true
	}
	return cut
}

// CutLabels cuts each value of a series label to maxChars characters and reports
// whether it cut one. It runs after redaction, as CutLines does. A field of a log
// line can be a label of a metric query, so a value is log text too.
func CutLabels(data *protocol.ResultData, maxChars int) bool {
	if maxChars <= 0 {
		return false
	}
	cut := false
	shorten := func(labels map[string]string) {
		for key, value := range labels {
			if utf8.RuneCountInString(value) > maxChars {
				labels[key] = string([]rune(strings.ToValidUTF8(value, "\uFFFD"))[:maxChars])
				cut = true
			}
		}
	}
	for _, series := range data.Series {
		shorten(series.Labels)
	}
	for _, sample := range data.Samples {
		shorten(sample.Labels)
	}
	return cut
}

// Names keeps the first maxItems names, in the source's order.
func Names(names []string, limits protocol.Limits) (data *protocol.ResultData, truncated bool) {
	kept, truncated := first(names, limits.MaxItems)
	return &protocol.ResultData{Kind: protocol.DataNames, Names: kept}, truncated
}

// Items keeps the first maxItems items.
func Items[T any](items []T, limits protocol.Limits) ([]T, bool) {
	return first(items, limits.MaxItems)
}

func first[T any](items []T, limit int) ([]T, bool) {
	if limit > 0 && len(items) > limit {
		return items[:limit], true
	}
	return items, false
}

// Fit drops items from the end of the data until its JSON fits maxBytes, and
// returns its size and whether it dropped anything. With maxBytes zero it only
// measures.
func Fit(data *protocol.ResultData, maxBytes int) (size int, truncated bool, err error) {
	for {
		encoded, err := json.Marshal(data)
		if err != nil {
			return 0, truncated, fmt.Errorf("encode result data: %w", err)
		}
		size = len(encoded)
		if maxBytes <= 0 || size <= maxBytes {
			return size, truncated, nil
		}
		if !dropItems(data, size, maxBytes) {
			return size, truncated, nil
		}
		truncated = true
	}
}

// dropItems shortens the longest list in proportion to the excess. It reports false
// when there is nothing left to drop.
func dropItems(data *protocol.ResultData, size, maxBytes int) bool {
	count := func(length int) int {
		excess := size - maxBytes
		return max(1, length*excess/size)
	}
	switch {
	case len(data.Series) > 0:
		data.Series = data.Series[:len(data.Series)-count(len(data.Series))]
	case len(data.Samples) > 0:
		data.Samples = data.Samples[:len(data.Samples)-count(len(data.Samples))]
	case len(data.Lines) > 0:
		data.Lines = data.Lines[:len(data.Lines)-count(len(data.Lines))]
	case len(data.Patterns) > 0:
		data.Patterns = data.Patterns[:len(data.Patterns)-count(len(data.Patterns))]
	case len(data.Names) > 0:
		data.Names = data.Names[:len(data.Names)-count(len(data.Names))]
	case len(data.Datasources) > 0:
		data.Datasources = data.Datasources[:len(data.Datasources)-count(len(data.Datasources))]
	case len(data.Dashboards) > 0:
		data.Dashboards = data.Dashboards[:len(data.Dashboards)-count(len(data.Dashboards))]
	case len(data.PanelQueries) > 0:
		data.PanelQueries = data.PanelQueries[:len(data.PanelQueries)-count(len(data.PanelQueries))]
	case len(data.AlertRules) > 0:
		data.AlertRules = data.AlertRules[:len(data.AlertRules)-count(len(data.AlertRules))]
	default:
		return false
	}
	return true
}
