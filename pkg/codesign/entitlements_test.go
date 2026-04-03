package codesign

import "testing"

func TestDefaultEntitlements(t *testing.T) {
	entitlements := DefaultEntitlements("APPPREFIX", "TEAMID", "com.example.app", true)

	if entitlements["application-identifier"] != "APPPREFIX.com.example.app" {
		t.Fatal("unexpected application-identifier")
	}
	if entitlements["com.apple.developer.team-identifier"] != "TEAMID" {
		t.Fatal("unexpected team identifier")
	}
	if entitlements["get-task-allow"] != true {
		t.Fatal("unexpected get-task-allow")
	}

	groupsRaw, ok := entitlements["keychain-access-groups"]
	if !ok {
		t.Fatal("missing keychain-access-groups")
	}

	groups, ok := groupsRaw.([]string)
	if !ok {
		t.Fatal("expected []string keychain-access-groups")
	}

	if len(groups) != 1 || groups[0] != "APPPREFIX.com.example.app" {
		t.Fatal("unexpected keychain-access-groups value")
	}
}
