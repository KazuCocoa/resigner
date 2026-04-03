package codesign

import "resigner/pkg/macho"

func DefaultEntitlements(teamIDPrefix, teamID, bundleID string, getTaskAllow bool) macho.Entitlements {
	appID := prefixedAppID(teamIDPrefix, bundleID)
	groups := make([]string, 1)
	groups[0] = appID

	entitlements := macho.Entitlements{}
	entitlements["application-identifier"] = appID
	entitlements["com.apple.developer.team-identifier"] = teamID
	entitlements["get-task-allow"] = getTaskAllow
	entitlements["keychain-access-groups"] = groups

	return entitlements
}

func prefixedAppID(prefix, bundleID string) string {
	if prefix == "" {
		return "." + bundleID
	}
	return prefix + "." + bundleID
}
