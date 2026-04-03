package codesign

// InfoPlist contains only the Info.plist keys required by the signing flow.
// Additional plist fields are intentionally omitted.
type InfoPlist struct {
	PlatformName string `plist:"DTPlatformName"`

	BundleExecutable string `plist:"CFBundleExecutable"`
	BundleIdentifier string `plist:"CFBundleIdentifier"`
	BundleVersion    string `plist:"CFBundleVersion"`
}
