package codesign

import (
	"context"
	"crypto/sha1"
	"io"
	stdfs "io/fs"
	"math"
	"path/filepath"
	"regexp"
	"sync"

	"howett.net/plist"
	"resigner/pkg/fs"

	sha256Simd "github.com/minio/sha256-simd"
)

func DefaultRulesV1() RulesV1 {
	return RulesV1{
		`^.*`: {},
		`^.*\.lproj/`: {
			Optional: true,
			Weight:   1000,
		},
		`^.*\.lproj/locversion.plist$`: {
			Omit:   true,
			Weight: 1100,
		},
		`^Base\.lproj/`: {
			Weight: 1010,
		},
		`^version.plist$`: {},
	}
}

func DefaultRulesV2() RulesV2 {
	return RulesV2{
		`.*\.dSYM($|/)`: {
			Weight: 11,
		},

		`^(.*/)?\.DS_Store$`: {
			Omit:   true,
			Weight: 2000,
		},
		`^.*`: {},
		`^.*\.lproj/`: {
			Optional: true,
			Weight:   1000,
		},
		`^.*\.lproj/locversion.plist$`: {
			Omit:   true,
			Weight: 1100,
		},
		`^Base\.lproj/`: {
			Weight: 1010,
		},
		`^Info\.plist$`: {
			Omit:   true,
			Weight: 20,
		},
		`^PkgInfo$`: {
			Omit:   true,
			Weight: 20,
		},
		`^embedded\.provisionprofile$`: {
			Weight: 20,
		},
		`^version\.plist$`: {
			Weight: 20,
		},
	}
}

type fileEntry struct {
	relPath string
	hsh1    []byte
	hsh2    []byte
}

type resourceBuilt struct {
	entry  fileEntry
	ruleV1 RuleV1
	ruleV2 RuleV2
}

func GenerateCodeResources(root fs.ReadWriteFS, path string) (*CodeResources, error) {
	infoFile, err := root.Open(filepath.Join(path, "Info.plist"))
	if err != nil {
		return nil, err
	}
	defer infoFile.Close()

	infoData, err := io.ReadAll(infoFile)
	if err != nil {
		return nil, err
	}

	var info InfoPlist
	_, err = plist.Unmarshal(infoData, &info)
	if err != nil {
		return nil, err
	}

	resources := &CodeResources{
		FilesV1: make(map[string]FileResourceV1),
		FilesV2: make(map[string]FileResourceV2),
		RulesV1: DefaultRulesV1(),
		RulesV2: DefaultRulesV2(),
	}

	// Collect files from filesystem
	filesToHash := make(chan string, 32)
	hashed := make(chan fileEntry, 32)
	applied := make(chan resourceBuilt, 32)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// File discovery: walk filesystem and push eligible paths
	go func() {
		defer close(filesToHash)
		stdfs.WalkDir(root, path, func(subPath string, d stdfs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}

			relPath, _ := filepath.Rel(path, subPath)
			if relPath == info.BundleExecutable || relPath == filepath.Join("_CodeSignature", "CodeResources") {
				return nil
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case filesToHash <- relPath:
			}
			return nil
		})
	}()

	// Hash pool: read files and compute hashes, push to rule application
	var hashWg sync.WaitGroup
	for i := 0; i < 4; i++ {
		hashWg.Add(1)
		go func() {
			defer hashWg.Done()
			for relPath := range filesToHash {
				h1, h2, err := resources.computeHashes(root, path, relPath)
				if err != nil {
					select {
					case <-ctx.Done():
					default:
						cancel()
					}
					return
				}
				select {
				case <-ctx.Done():
					return
				case hashed <- fileEntry{relPath: relPath, hsh1: h1, hsh2: h2}:
				}
			}
		}()
	}

	// Close hashed when all hashers done
	go func() {
		hashWg.Wait()
		close(hashed)
	}()

	// Rule application: apply rules to hashes, collect results
	var ruleWg sync.WaitGroup
	for i := 0; i < 4; i++ {
		ruleWg.Add(1)
		go func() {
			defer ruleWg.Done()
			for entry := range hashed {
				r1, _ := resources.RulesV1.Rule(entry.relPath)
				r2, _ := resources.RulesV2.Rule(entry.relPath)

				if !r1.Omit || !r2.Omit {
					select {
					case <-ctx.Done():
						return
					case applied <- resourceBuilt{
						entry:  entry,
						ruleV1: r1,
						ruleV2: r2,
					}:
					}
				}
			}
		}()
	}

	// Close applied when all rule appliers done
	go func() {
		ruleWg.Wait()
		close(applied)
	}()

	// Collect results
	for res := range applied {
		if !res.ruleV1.Omit {
			resources.FilesV1[res.entry.relPath] = FileResourceV1{
				Hash:     res.entry.hsh1,
				Optional: res.ruleV1.Optional,
			}
		}
		if !res.ruleV2.Omit {
			resources.FilesV2[res.entry.relPath] = FileResourceV2{
				Hash:     res.entry.hsh1,
				Hash2:    res.entry.hsh2,
				Optional: res.ruleV2.Optional,
			}
		}
	}

	return resources, ctx.Err()
}

func (r *CodeResources) computeHashes(root fs.FS, base, path string) ([]byte, []byte, error) {
	f, err := root.Open(filepath.Join(base, path))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	h1, h2 := sha1.New(), sha256Simd.New()
	_, err = io.Copy(io.MultiWriter(h1, h2), f)
	if err != nil {
		return nil, nil, err
	}

	return h1.Sum(nil), h2.Sum(nil), nil
}

type CodeResources struct {
	FilesV1 map[string]FileResourceV1 `plist:"files"`
	FilesV2 map[string]FileResourceV2 `plist:"files2"`
	RulesV1 RulesV1                   `plist:"rules"`
	RulesV2 RulesV2                   `plist:"rules2"`
}

func (r *CodeResources) AddResource(root fs.FS, base, path string) error {
	if r.FilesV1 == nil {
		r.FilesV1 = make(map[string]FileResourceV1)
	}
	if r.FilesV2 == nil {
		r.FilesV2 = make(map[string]FileResourceV2)
	}

	hsh1, hsh256, err := r.computeHashes(root, base, path)
	if err != nil {
		return err
	}

	ruleV1, _ := r.RulesV1.Rule(path)
	if !ruleV1.Omit {
		r.FilesV1[path] = FileResourceV1{
			Hash:     hsh1,
			Optional: ruleV1.Optional,
		}
	}

	ruleV2, _ := r.RulesV2.Rule(path)
	if !ruleV2.Omit {
		r.FilesV2[path] = FileResourceV2{
			Hash:     hsh1,
			Hash2:    hsh256,
			Optional: ruleV2.Optional,
		}
	}

	return nil
}

func (r *CodeResources) SetResource(filename string, hash, hash2 []byte, optional bool) {
	if r.FilesV1 == nil {
		r.FilesV1 = make(map[string]FileResourceV1)
	}
	if r.FilesV2 == nil {
		r.FilesV2 = make(map[string]FileResourceV2)
	}
	r.FilesV1[filename] = FileResourceV1{Hash: hash, Optional: optional}
	r.FilesV2[filename] = FileResourceV2{Hash: hash, Hash2: hash2, Optional: optional}
}

func (r *CodeResources) FillDefaultRules() {
	if r.FilesV1 == nil {
		r.FilesV1 = make(map[string]FileResourceV1)
	}
	if r.FilesV2 == nil {
		r.FilesV2 = make(map[string]FileResourceV2)
	}
	if r.RulesV1 == nil {
		r.RulesV1 = DefaultRulesV1()
	}
	if r.RulesV2 == nil {
		r.RulesV2 = DefaultRulesV2()
	}
}

type rawFileResourceV1 struct {
	Hash     []byte `plist:"hash"`
	Optional bool   `plist:"optional,omitempty"`
}

type FileResourceV1 rawFileResourceV1

var _ plist.Marshaler = FileResourceV1{}
var _ plist.Unmarshaler = &FileResourceV1{}

func (r FileResourceV1) MarshalPlist() (interface{}, error) {
	if !r.Optional {
		return r.Hash, nil
	}
	return rawFileResourceV1(r), nil
}

func (r *FileResourceV1) UnmarshalPlist(unmarshal func(interface{}) error) error {
	err := unmarshal(&r.Hash)
	if err != nil {
		return unmarshal((*rawFileResourceV1)(r))
	}
	return nil
}

type rawFileResourceV2 struct {
	Hash     []byte `plist:"hash"`
	Hash2    []byte `plist:"hash2"`
	Optional bool   `plist:"optional,omitempty"`
}

type FileResourceV2 rawFileResourceV2

var _ plist.Marshaler = FileResourceV2{}
var _ plist.Unmarshaler = &FileResourceV2{}

func (r FileResourceV2) MarshalPlist() (interface{}, error) {
	return rawFileResourceV2(r), nil
}

func (r *FileResourceV2) UnmarshalPlist(unmarshal func(interface{}) error) error {
	return unmarshal((*rawFileResourceV2)(r))
}

type rawRuleV1 struct {
	Omit     bool    `plist:"omit,omitempty"`
	Optional bool    `plist:"optional,omitempty"`
	Weight   float64 `plist:"weight"`
}

type RuleV1 rawRuleV1

var _ plist.Marshaler = RuleV1{}
var _ plist.Unmarshaler = &RuleV1{}

func (r RuleV1) MarshalPlist() (interface{}, error) {
	if !r.Omit && r.Weight == 0 && !r.Optional {
		return true, nil
	}
	return rawRuleV1(r), nil
}

func (r *RuleV1) UnmarshalPlist(unmarshal func(interface{}) error) error {
	var enable bool
	err := unmarshal(&enable)
	if err != nil {
		return unmarshal((*rawRuleV1)(r))
	}
	*r = RuleV1{}
	return nil
}

type rawRuleV2 struct {
	Omit     bool    `plist:"omit,omitempty"`
	Optional bool    `plist:"optional,omitempty"`
	Weight   float64 `plist:"weight"`
}

type RuleV2 rawRuleV2

var _ plist.Marshaler = RuleV2{}
var _ plist.Unmarshaler = &RuleV2{}

func (r RuleV2) MarshalPlist() (interface{}, error) {
	if !r.Omit && r.Weight == 0 && !r.Optional {
		return true, nil
	}
	return rawRuleV2(r), nil
}

func (r *RuleV2) UnmarshalPlist(unmarshal func(interface{}) error) error {
	var enable bool
	err := unmarshal(&enable)
	if err != nil {
		return unmarshal((*rawRuleV2)(r))
	}
	*r = RuleV2{}
	return nil
}

type RulesV1 map[string]RuleV1

func (r RulesV1) Rule(path string) (RuleV1, error) {
	best := findBestRuleV1(r, path)
	return best, nil
}

type RulesV2 map[string]RuleV2

func (r RulesV2) Rule(path string) (RuleV2, error) {
	best := findBestRuleV2(r, path)
	return best, nil
}

func findBestRuleV1(ruleMap RulesV1, path string) RuleV1 {
	var result RuleV1
	maxWeight := math.Inf(-1)

	for pattern, rule := range ruleMap {
		match, _ := regexp.MatchString(pattern, path)
		if match && rule.Weight > maxWeight {
			maxWeight = rule.Weight
			result = rule
		}
	}

	return result
}

func findBestRuleV2(ruleMap RulesV2, path string) RuleV2 {
	var result RuleV2
	maxWeight := math.Inf(-1)

	for pattern, rule := range ruleMap {
		match, _ := regexp.MatchString(pattern, path)
		if match && rule.Weight > maxWeight {
			maxWeight = rule.Weight
			result = rule
		}
	}

	return result
}
