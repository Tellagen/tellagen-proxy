package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/reduce"
	"github.com/tellagen/tellagen-proxy/protocol"
)

// The decoders read named fields only. Anything else in an answer, such as hints,
// parsed labels and structured metadata, never gets past this file.

type prometheusPoint struct {
	at    time.Time
	value float64
}

// UnmarshalJSON reads Prometheus's [1730000000.5, "1.25"]. A value of NaN or Inf
// stays as that float, and the reducers treat it as a gap.
func (p *prometheusPoint) UnmarshalJSON(data []byte) error {
	var pair [2]json.RawMessage
	if err := json.Unmarshal(data, &pair); err != nil {
		return err
	}
	var seconds float64
	if err := json.Unmarshal(pair[0], &seconds); err != nil {
		return err
	}
	var text string
	if err := json.Unmarshal(pair[1], &text); err != nil {
		return err
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return err
	}
	whole, fraction := math.Modf(seconds)
	p.at = time.Unix(int64(whole), int64(fraction*1e9)).UTC().Truncate(time.Millisecond)
	p.value = value
	return nil
}

type prometheusSeries struct {
	Metric map[string]string `json:"metric"`
	Values []prometheusPoint `json:"values"`
	Value  *prometheusPoint  `json:"value"`
}

func (s prometheusSeries) points() []reduce.Point {
	points := make([]reduce.Point, 0, len(s.Values))
	for _, point := range s.Values {
		points = append(points, reduce.Point{At: point.at, Value: point.value})
	}
	return points
}

func decodePrometheus(text string) ([]prometheusSeries, error) {
	var answer struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(text), &answer); err != nil {
		return nil, err
	}
	if len(answer.Data) == 0 || string(answer.Data) == "null" {
		return nil, nil
	}
	var series []prometheusSeries
	if err := json.Unmarshal(answer.Data, &series); err != nil {
		return nil, err
	}
	return series, nil
}

type lokiEntry struct {
	Timestamp string            `json:"timestamp"`
	Line      string            `json:"line"`
	Value     *float64          `json:"value"`
	Values    []lokiMetricValue `json:"values"`
	Labels    map[string]string `json:"labels"`
}

type lokiMetricValue struct {
	Timestamp string  `json:"timestamp"`
	Value     float64 `json:"value"`
}

func (e lokiEntry) points() []reduce.Point {
	points := make([]reduce.Point, 0, len(e.Values))
	for _, value := range e.Values {
		at, err := parseLokiTimestamp(value.Timestamp)
		if err != nil {
			continue
		}
		points = append(points, reduce.Point{At: at, Value: value.Value})
	}
	return points
}

func decodeLoki(text string) ([]lokiEntry, error) {
	var answer struct {
		Data *[]lokiEntry `json:"data"`
	}
	if err := json.Unmarshal([]byte(text), &answer); err != nil {
		return nil, err
	}
	if answer.Data == nil {
		return nil, errors.New("the answer has no data field")
	}
	return *answer.Data, nil
}

// parseLokiTimestamp reads the forms grafana-mcp uses: seconds with a fraction, and
// nanoseconds as a string of digits.
func parseLokiTimestamp(text string) (time.Time, error) {
	if text == "" {
		return time.Time{}, errors.New("no timestamp")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, text); err == nil {
		return parsed.UTC(), nil
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp %q: %w", text, err)
	}
	const nanosecondDigits = 1e15
	if value > nanosecondDigits {
		nanos, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("timestamp %q: %w", text, err)
		}
		return time.Unix(0, nanos).UTC(), nil
	}
	whole, fraction := math.Modf(value)
	return time.Unix(int64(whole), int64(fraction*1e9)).UTC().Truncate(time.Millisecond), nil
}

func decodeDatasources(text string) ([]protocol.Datasource, error) {
	var answer struct {
		Datasources []struct {
			UID       string `json:"uid"`
			Name      string `json:"name"`
			Type      string `json:"type"`
			IsDefault bool   `json:"isDefault"`
		} `json:"datasources"`
	}
	if err := json.Unmarshal([]byte(text), &answer); err != nil {
		return nil, err
	}
	out := make([]protocol.Datasource, 0, len(answer.Datasources))
	for _, one := range answer.Datasources {
		out = append(out, protocol.Datasource{UID: one.UID, Name: one.Name, Type: one.Type, Default: one.IsDefault})
	}
	return out, nil
}
