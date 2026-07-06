package roles

import "testing"

func TestNormalizeBuiltInRoles(t *testing.T) {
	tests := []struct {
		name string
		role string
		want Kind
	}{
		{name: "english super admin", role: "super-admin", want: SuperAdmin},
		{name: "chinese super admin", role: "超级管理员", want: SuperAdmin},
		{name: "english admin", role: "administrator", want: Admin},
		{name: "chinese admin", role: "管理员", want: Admin},
		{name: "chinese auditor", role: "审计员", want: Auditor},
		{name: "chinese user", role: "普通用户", want: User},
		{name: "custom", role: "asset-operator", want: Custom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Normalize(tt.role); got != tt.want {
				t.Fatalf("Normalize(%q) = %q, want %q", tt.role, got, tt.want)
			}
		})
	}
}
