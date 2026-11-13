// Package policy holds the local policy file and what Tellagen's settings may do
// inside it: an update can only tighten the file, never loosen it.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tellagen/tellagen-proxy/protocol"
	"github.com/tellagen/tellagen-proxy/redact"
)

// The defaults of a proxy with no policy file. A file can change them, within the
// ceilings below and in package protocol. logs.maxScanBytes has no ceiling.
const (
	// DefaultQueryTimeout applies when neither Tellagen nor the command sets a
	// timeout. query.maxTimeout bounds what they can set.
	DefaultQueryTimeout = 20 * time.Second

	defaultMaxTimeout     = 60 * time.Second
	defaultMaxResultBytes = 64 * 1024
	defaultMaxPerRun      = 40
	defaultMaxScanBytes   = 10 << 30

	// maxPerRunCeiling is the most commands per run that read data. List and search
	// commands have their own limit, protocol.DiscoveryCommandsPerRun, which a file
	// can lower with query.maxListPerRun.
	maxPerRunCeiling = 200
	// MaxConcurrentCeiling is the binary's highest number of queries at a time. A
	// policy file can only lower it.
	MaxConcurrentCeiling = 2
)

// File is the parsed local policy file.
type File struct {
	// DatasourceUIDs is nil when the file names no list. Tellagen's list then
	// decides alone, and it starts empty.
	DatasourceUIDs []string
	// Capabilities is nil when the file allows every capability.
	Capabilities      []string
	MaxPerRun         int
	MaxListPerRun     int
	MaxConcurrent     int
	MaxScanBytes      int64
	EnforcedMatchers  []string
	RedactionAllowOff bool
	ExtraRules        []protocol.RedactionRule

	limits   map[string]protocol.Limits
	revision string
}

type fileDocument struct {
	DatasourceUIDs *[]string `yaml:"datasourceUIDs"`
	Capabilities   *[]string `yaml:"capabilities"`
	Query          struct {
		MaxTimeout     *duration `yaml:"maxTimeout"`
		MaxPerRun      *int      `yaml:"maxPerRun"`
		MaxListPerRun  *int      `yaml:"maxListPerRun"`
		MaxConcurrent  *int      `yaml:"maxConcurrent"`
		MaxResultBytes *int      `yaml:"maxResultBytes"`
		MaxItems       *int      `yaml:"maxItems"`
	} `yaml:"query"`
	Metrics struct {
		MaxRange  *duration `yaml:"maxRange"`
		MaxPoints *int      `yaml:"maxPoints"`
		MaxSeries *int      `yaml:"maxSeries"`
	} `yaml:"metrics"`
	Logs struct {
		MaxRange         *duration `yaml:"maxRange"`
		MaxPoints        *int      `yaml:"maxPoints"`
		MaxSeries        *int      `yaml:"maxSeries"`
		MaxLines         *int      `yaml:"maxLines"`
		MaxLineChars     *int      `yaml:"maxLineChars"`
		MaxPatterns      *int      `yaml:"maxPatterns"`
		MaxScanBytes     *int64    `yaml:"maxScanBytes"`
		EnforcedMatchers []string  `yaml:"enforcedMatchers"`
	} `yaml:"logs"`
	Redaction struct {
		AllowOff   *bool `yaml:"allowOff"`
		ExtraRules []struct {
			Kind  string `yaml:"kind"`
			Key   string `yaml:"key"`
			Regex string `yaml:"regex"`
		} `yaml:"extraRules"`
	} `yaml:"redaction"`
}

type duration time.Duration

// UnmarshalYAML reads a duration such as 60s.
func (d *duration) UnmarshalYAML(node *yaml.Node) error {
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("line %d: %q is not a duration such as 60s", node.Line, node.Value)
	}
	*d = duration(parsed)
	return nil
}

// Load reads the policy file at path. An empty path means no policy file. A file
// that cannot be read or understood is an error and the proxy must not start, so
// that a typo in a limit never becomes a looser limit. allowedDatasourceUIDs
// (GRAFANA_ALLOWED_DATASOURCE_UIDS), when set, is the list if the file names none
// and otherwise removes the UIDs of the file that it does not hold.
func Load(path string, allowedDatasourceUIDs []string) (*File, error) {
	var data []byte
	if path != "" {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read policy file: %w", err)
		}
	}
	file, err := parseFile(data)
	if err != nil {
		return nil, fmt.Errorf("policy file %s: %w", path, err)
	}
	if allowedDatasourceUIDs != nil {
		if file.DatasourceUIDs == nil {
			file.DatasourceUIDs = slices.Clone(allowedDatasourceUIDs)
		} else {
			file.DatasourceUIDs = slices.DeleteFunc(file.DatasourceUIDs, func(uid string) bool {
				return !slices.Contains(allowedDatasourceUIDs, uid)
			})
		}
	}
	return file, nil
}

func parseFile(data []byte) (*File, error) {
	var document fileDocument
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	file := &File{
		MaxPerRun:        defaultMaxPerRun,
		MaxListPerRun:    protocol.DiscoveryCommandsPerRun,
		MaxConcurrent:    MaxConcurrentCeiling,
		MaxScanBytes:     defaultMaxScanBytes,
		EnforcedMatchers: document.Logs.EnforcedMatchers,
	}
	sum := sha256.Sum256(data)
	file.revision = "sha256:" + hex.EncodeToString(sum[:])

	if document.DatasourceUIDs != nil {
		file.DatasourceUIDs = append([]string{}, *document.DatasourceUIDs...)
	}
	if document.Capabilities != nil {
		file.Capabilities = append([]string{}, *document.Capabilities...)
		for _, capability := range file.Capabilities {
			if !protocol.IsKnownCapability(capability) {
				return nil, fmt.Errorf("capabilities: unknown capability %q", capability)
			}
		}
	}
	if document.Redaction.AllowOff != nil {
		file.RedactionAllowOff = *document.Redaction.AllowOff
	}
	for _, rule := range document.Redaction.ExtraRules {
		file.ExtraRules = append(file.ExtraRules, protocol.RedactionRule{Kind: rule.Kind, Key: rule.Key, Regex: rule.Regex})
	}
	if _, errs := redact.New(file.ExtraRules); len(errs) > 0 {
		return nil, fmt.Errorf("redaction.extraRules: %s", errs[0].Reason)
	}

	if err := file.applyLimits(&document); err != nil {
		return nil, err
	}
	return file, nil
}

// applyLimits reads the numeric settings of the document into the file, or
// returns every problem it found.
func (f *File) applyLimits(document *fileDocument) error {
	var problems []error
	number := func(name string, value *int, target *int) {
		switch {
		case value == nil:
		case *value <= 0:
			problems = append(problems, fmt.Errorf("%s must be above zero", name))
		default:
			*target = *value
		}
	}
	seconds := func(name string, value *duration, target *int) {
		switch {
		case value == nil:
		case *value < duration(time.Second):
			problems = append(problems, fmt.Errorf("%s must be at least 1s", name))
		default:
			*target = int(time.Duration(*value) / time.Second)
		}
	}

	shared := protocol.Limits{TimeoutMS: int(defaultMaxTimeout / time.Millisecond), MaxResultBytes: defaultMaxResultBytes, MaxItems: 200}
	if value := document.Query.MaxTimeout; value != nil {
		if *value < duration(time.Second) {
			problems = append(problems, errors.New("query.maxTimeout must be at least 1s"))
		} else {
			shared.TimeoutMS = int(time.Duration(*value) / time.Millisecond)
		}
	}
	number("query.maxResultBytes", document.Query.MaxResultBytes, &shared.MaxResultBytes)
	number("query.maxItems", document.Query.MaxItems, &shared.MaxItems)
	number("query.maxPerRun", document.Query.MaxPerRun, &f.MaxPerRun)
	number("query.maxConcurrent", document.Query.MaxConcurrent, &f.MaxConcurrent)
	number("query.maxListPerRun", document.Query.MaxListPerRun, &f.MaxListPerRun)
	f.MaxPerRun = min(f.MaxPerRun, maxPerRunCeiling)
	f.MaxListPerRun = min(f.MaxListPerRun, protocol.DiscoveryCommandsPerRun)
	f.MaxConcurrent = min(f.MaxConcurrent, MaxConcurrentCeiling)
	if value := document.Logs.MaxScanBytes; value != nil {
		if *value <= 0 {
			problems = append(problems, errors.New("logs.maxScanBytes must be above zero"))
		} else {
			f.MaxScanBytes = *value
		}
	}

	metrics := shared
	metrics.MaxRangeS, metrics.MaxPoints, metrics.MaxSeries = 24*60*60, 500, 20
	seconds("metrics.maxRange", document.Metrics.MaxRange, &metrics.MaxRangeS)
	number("metrics.maxPoints", document.Metrics.MaxPoints, &metrics.MaxPoints)
	number("metrics.maxSeries", document.Metrics.MaxSeries, &metrics.MaxSeries)

	logs := shared
	logs.MaxRangeS, logs.MaxPoints, logs.MaxSeries = 6*60*60, 500, 20
	logs.MaxLines, logs.MaxLineChars, logs.MaxPatterns = 20, 500, 5
	seconds("logs.maxRange", document.Logs.MaxRange, &logs.MaxRangeS)
	number("logs.maxPoints", document.Logs.MaxPoints, &logs.MaxPoints)
	number("logs.maxSeries", document.Logs.MaxSeries, &logs.MaxSeries)
	number("logs.maxLines", document.Logs.MaxLines, &logs.MaxLines)
	number("logs.maxLineChars", document.Logs.MaxLineChars, &logs.MaxLineChars)
	number("logs.maxPatterns", document.Logs.MaxPatterns, &logs.MaxPatterns)

	if len(problems) > 0 {
		return errors.Join(problems...)
	}
	f.limits = map[string]protocol.Limits{
		protocol.FamilyPrometheus: clampToBinary(protocol.FamilyPrometheus, metrics),
		protocol.FamilyLoki:       clampToBinary(protocol.FamilyLoki, logs),
		protocol.FamilyGrafana:    clampToBinary(protocol.FamilyGrafana, shared),
	}
	return nil
}

// clampToBinary lowers a family's limits to the highest ceiling of any capability
// in that family, so that the file's values are what actually can apply.
func clampToBinary(family string, limits protocol.Limits) protocol.Limits {
	highest := protocol.Limits{}
	for _, capability := range protocol.Capabilities() {
		if protocol.CapabilityFamily(capability.Name) != family {
			continue
		}
		c := capability.Limits
		highest.MaxRangeS = max(highest.MaxRangeS, c.MaxRangeS)
		highest.MaxPoints = max(highest.MaxPoints, c.MaxPoints)
		highest.MaxSeries = max(highest.MaxSeries, c.MaxSeries)
		highest.TimeoutMS = max(highest.TimeoutMS, c.TimeoutMS)
		highest.MaxResultBytes = max(highest.MaxResultBytes, c.MaxResultBytes)
		highest.MaxLines = max(highest.MaxLines, c.MaxLines)
		highest.MaxLineChars = max(highest.MaxLineChars, c.MaxLineChars)
		highest.MaxPatterns = max(highest.MaxPatterns, c.MaxPatterns)
		highest.MaxItems = max(highest.MaxItems, c.MaxItems)
	}
	return limits.Narrow(highest)
}

// Revision identifies the file's content. Only tests use it.
func (f *File) Revision() string {
	return f.revision
}
