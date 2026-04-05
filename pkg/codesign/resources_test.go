package codesign

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	stdlibfs "io/fs"

	"howett.net/plist"
	"resigner/pkg/fs"
)

func writeFile(t *testing.T, root, relPath string, data []byte) {
	t.Helper()

	absPath := filepath.Join(root, relPath)
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(absPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRulesV1Rule_UsesHighestWeightMatch(t *testing.T) {
	rules := RulesV1{
		`^.*$`:           {},
		`^foo/`:          {Optional: true, Weight: 10},
		`^foo/bar\.txt$`: {Omit: true, Weight: 20},
	}

	rule, err := rules.Rule("foo/bar.txt")
	if err != nil {
		t.Fatal(err)
	}

	if !rule.Omit {
		t.Fatal("expected highest weight rule to omit")
	}

	if rule.Optional {
		t.Fatal("expected highest weight rule fields without lower-weight merge")
	}
}

func TestRulesV2Rule_UsesHighestWeightMatch(t *testing.T) {
	rules := RulesV2{
		`^.*$`:                          {},
		`^.*\.lproj/`:                   {Optional: true, Weight: 1000},
		`^.*\.lproj/locversion\.plist$`: {Omit: true, Weight: 1100},
	}

	rule, err := rules.Rule("en.lproj/locversion.plist")
	if err != nil {
		t.Fatal(err)
	}

	if !rule.Omit {
		t.Fatal("expected highest weight rule to omit")
	}

	if rule.Optional {
		t.Fatal("expected highest weight rule fields without lower-weight merge")
	}
}

func TestFileResourceV1_MarshalUnmarshal_RoundTrip(t *testing.T) {
	type container struct {
		Resource FileResourceV1 `plist:"resource"`
	}

	original := container{Resource: FileResourceV1{Hash: []byte{1, 2, 3, 4}}}
	data, err := plist.Marshal(original, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	var decoded container
	if _, err := plist.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded.Resource.Hash, original.Resource.Hash) {
		t.Fatal("hash mismatch after roundtrip")
	}

	if decoded.Resource.Optional {
		t.Fatal("unexpected optional flag")
	}

	original.Resource.Optional = true
	data, err = plist.Marshal(original, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := plist.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if !decoded.Resource.Optional {
		t.Fatal("expected optional flag after roundtrip")
	}
}

func TestRuleV1_MarshalUnmarshal_RoundTrip(t *testing.T) {
	type container struct {
		Rule RuleV1 `plist:"rule"`
	}

	original := container{Rule: RuleV1{}}
	data, err := plist.Marshal(original, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	var decoded container
	if _, err := plist.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Rule.Omit || decoded.Rule.Optional || decoded.Rule.Weight != 0 {
		t.Fatal("expected default bool form to decode into zero-value rule")
	}

	original.Rule = RuleV1{Omit: true, Optional: true, Weight: 42}
	data, err = plist.Marshal(original, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := plist.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if !decoded.Rule.Omit || !decoded.Rule.Optional || decoded.Rule.Weight != 42 {
		t.Fatal("expected structured rule to roundtrip")
	}
}

func TestFileResourceV2_MarshalUnmarshal_RoundTrip(t *testing.T) {
	type container struct {
		Resource FileResourceV2 `plist:"resource"`
	}

	original := container{Resource: FileResourceV2{Hash: []byte{1, 2, 3}, Hash2: []byte{4, 5, 6}, Optional: true}}
	data, err := plist.Marshal(original, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	var decoded container
	if _, err := plist.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded.Resource.Hash, original.Resource.Hash) {
		t.Fatal("hash mismatch after roundtrip")
	}

	if !bytes.Equal(decoded.Resource.Hash2, original.Resource.Hash2) {
		t.Fatal("hash2 mismatch after roundtrip")
	}

	if !decoded.Resource.Optional {
		t.Fatal("expected optional flag after roundtrip")
	}
}

func TestRuleV2_MarshalUnmarshal_RoundTrip(t *testing.T) {
	type container struct {
		Rule RuleV2 `plist:"rule"`
	}

	original := container{Rule: RuleV2{}}
	data, err := plist.Marshal(original, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	var decoded container
	if _, err := plist.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Rule.Omit || decoded.Rule.Optional || decoded.Rule.Weight != 0 {
		t.Fatal("expected default bool form to decode into zero-value rule")
	}

	original.Rule = RuleV2{Omit: true, Optional: true, Weight: 21}
	data, err = plist.Marshal(original, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := plist.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if !decoded.Rule.Omit || !decoded.Rule.Optional || decoded.Rule.Weight != 21 {
		t.Fatal("expected structured rule to roundtrip")
	}
}

func TestCodeResourcesSetResource_FillsBothVersions(t *testing.T) {
	var resources CodeResources

	h1 := []byte{1, 2, 3}
	h2 := []byte{4, 5, 6, 7}
	resources.SetResource("foo.txt", h1, h2, true)

	v1, ok := resources.FilesV1["foo.txt"]
	if !ok {
		t.Fatal("expected file in v1 map")
	}

	v2, ok := resources.FilesV2["foo.txt"]
	if !ok {
		t.Fatal("expected file in v2 map")
	}

	if !bytes.Equal(v1.Hash, h1) || !v1.Optional {
		t.Fatal("unexpected v1 resource values")
	}

	if !bytes.Equal(v2.Hash, h1) || !bytes.Equal(v2.Hash2, h2) || !v2.Optional {
		t.Fatal("unexpected v2 resource values")
	}
}

func TestCodeResourcesFillDefaultRules_InitializesMaps(t *testing.T) {
	var resources CodeResources

	resources.FillDefaultRules()

	if resources.FilesV1 == nil || resources.FilesV2 == nil || resources.RulesV1 == nil || resources.RulesV2 == nil {
		t.Fatal("expected FillDefaultRules to initialize all maps")
	}
}

func TestCodeResourcesAddResource_RespectsRules(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, tmp, "en.lproj/locversion.plist", []byte("skip"))
	writeFile(t, tmp, "en.lproj/strings.txt", []byte("localized"))
	writeFile(t, tmp, ".DS_Store", []byte("ds"))

	resources := CodeResources{RulesV1: DefaultRulesV1(), RulesV2: DefaultRulesV2()}

	if err := resources.AddResource(os.DirFS(tmp), ".", "en.lproj/locversion.plist"); err != nil {
		t.Fatal(err)
	}
	if err := resources.AddResource(os.DirFS(tmp), ".", "en.lproj/strings.txt"); err != nil {
		t.Fatal(err)
	}
	if err := resources.AddResource(os.DirFS(tmp), ".", ".DS_Store"); err != nil {
		t.Fatal(err)
	}

	if _, ok := resources.FilesV1["en.lproj/locversion.plist"]; ok {
		t.Fatal("expected locversion file to be omitted from v1")
	}

	if _, ok := resources.FilesV2["en.lproj/locversion.plist"]; ok {
		t.Fatal("expected locversion file to be omitted from v2")
	}

	locV1, ok := resources.FilesV1["en.lproj/strings.txt"]
	if !ok || !locV1.Optional {
		t.Fatal("expected localized file to be optional in v1")
	}

	locV2, ok := resources.FilesV2["en.lproj/strings.txt"]
	if !ok || !locV2.Optional {
		t.Fatal("expected localized file to be optional in v2")
	}

	if _, ok := resources.FilesV1[".DS_Store"]; !ok {
		t.Fatal("expected .DS_Store to be present in v1")
	}

	if _, ok := resources.FilesV2[".DS_Store"]; ok {
		t.Fatal("expected .DS_Store to be omitted from v2")
	}
}

func TestGenerateCodeResources_EndToEnd(t *testing.T) {
	tmp := t.TempDir()

	info := InfoPlist{BundleExecutable: "MyApp"}
	infoData, err := plist.Marshal(info, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	writeFile(t, tmp, "Info.plist", infoData)
	writeFile(t, tmp, "MyApp", []byte("binary"))
	writeFile(t, tmp, "_CodeSignature/CodeResources", []byte("old-signature"))
	writeFile(t, tmp, "PkgInfo", []byte("pkginfo"))
	writeFile(t, tmp, "embedded.provisionprofile", []byte("profile"))
	writeFile(t, tmp, "version.plist", []byte("version"))
	writeFile(t, tmp, ".DS_Store", []byte("ds"))
	writeFile(t, tmp, "en.lproj/locversion.plist", []byte("locversion"))
	writeFile(t, tmp, "en.lproj/strings.txt", []byte("localized text"))
	writeFile(t, tmp, "assets/data.txt", []byte("payload"))

	resources, err := GenerateCodeResources(fs.DirFS(tmp), ".")
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := resources.FilesV1["MyApp"]; ok {
		t.Fatal("bundle executable should be excluded")
	}

	if _, ok := resources.FilesV1["_CodeSignature/CodeResources"]; ok {
		t.Fatal("existing code resources file should be excluded")
	}

	if _, ok := resources.FilesV2["Info.plist"]; ok {
		t.Fatal("Info.plist should be omitted by v2 rules")
	}

	if _, ok := resources.FilesV1["Info.plist"]; !ok {
		t.Fatal("Info.plist should be included by v1 rules")
	}

	if _, ok := resources.FilesV2[".DS_Store"]; ok {
		t.Fatal(".DS_Store should be omitted by v2 rules")
	}

	localizedV2, ok := resources.FilesV2["en.lproj/strings.txt"]
	if !ok || !localizedV2.Optional {
		t.Fatal("localized files should be optional in v2")
	}

	if _, ok := resources.FilesV1["en.lproj/locversion.plist"]; ok {
		t.Fatal("locversion should be omitted by v1 rules")
	}

	if _, ok := resources.FilesV2["en.lproj/locversion.plist"]; ok {
		t.Fatal("locversion should be omitted by v2 rules")
	}

	asset, ok := resources.FilesV2["assets/data.txt"]
	if !ok {
		t.Fatal("expected regular file to be included")
	}

	if len(asset.Hash) != 20 {
		t.Fatal("expected SHA1 hash in v2 resource")
	}

	if len(asset.Hash2) != 32 {
		t.Fatal("expected SHA256 hash in v2 resource")
	}

	if _, err := stdlibfs.Stat(fs.DirFS(tmp), "_CodeSignature/CodeResources"); err != nil {
		t.Fatal(err)
	}
}

func TestCodeResourcesFixtures_RoundTrip(t *testing.T) {
	tests := []string{"CodeResources.simple", "CodeResources.complex"}

	for _, fixture := range tests {
		t.Run(fixture, func(t *testing.T) {
			fileData, err := os.ReadFile(filepath.Join("testdata", fixture))
			if err != nil {
				t.Fatal(err)
			}

			var resources CodeResources
			if _, err := plist.Unmarshal(fileData, &resources); err != nil {
				t.Fatal(err)
			}

			data, err := plist.MarshalIndent(resources, plist.XMLFormat, "    ")
			if err != nil {
				t.Fatal(err)
			}

			var decodedRoundTrip CodeResources
			if _, err := plist.Unmarshal(data, &decodedRoundTrip); err != nil {
				t.Fatal(err)
			}

			if len(decodedRoundTrip.FilesV1) == 0 && len(decodedRoundTrip.FilesV2) == 0 {
				t.Fatal("expected fixture to contain resources")
			}

			if len(resources.FilesV1) > 0 {
				for path := range resources.FilesV1 {
					if _, ok := decodedRoundTrip.FilesV1[path]; !ok {
						t.Fatalf("missing v1 resource after roundtrip: %s", path)
					}
					break
				}
			}

			if len(resources.FilesV2) > 0 {
				for path := range resources.FilesV2 {
					if _, ok := decodedRoundTrip.FilesV2[path]; !ok {
						t.Fatalf("missing v2 resource after roundtrip: %s", path)
					}
					break
				}
			}
		})
	}
}
