package roles

import "strings"

type Kind string

const (
	SuperAdmin Kind = "super_admin"
	Admin      Kind = "admin"
	Auditor    Kind = "auditor"
	User       Kind = "user"
	Custom     Kind = "custom"
)

func Normalize(rawRole string) Kind {
	value := strings.ToLower(strings.TrimSpace(rawRole))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, "　", "_")
	switch value {
	case "super_admin", "superadmin", "root", "owner", "超级管理员", "瓒呯骇绠＄悊鍛":
		return SuperAdmin
	case "admin", "administrator", "管理员", "绠＄悊鍛":
		return Admin
	case "auditor", "audit", "审计员", "瀹¤鍛":
		return Auditor
	case "user", "member", "普通用户", "鏅€氱敤鎴":
		return User
	default:
		return Custom
	}
}

func IsAdmin(rawRole string) bool {
	kind := Normalize(rawRole)
	return kind == SuperAdmin || kind == Admin
}
