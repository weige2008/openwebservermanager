package app

import (
	"net/http"
	"strings"

	"openwebservermanager/internal/model"
)

type roleKind string

const (
	roleSuperAdmin roleKind = "super_admin"
	roleAdmin      roleKind = "admin"
	roleAuditor    roleKind = "auditor"
	roleUser       roleKind = "user"
	roleCustom     roleKind = "custom"
)

type roleDecision struct {
	Kind        roleKind
	Permissions []string
}

func (s *Server) authorizeAPI(w http.ResponseWriter, r *http.Request) bool {
	if isAlwaysAllowedAuthenticatedAPI(r) {
		return true
	}
	_, session, ok := s.auth.session(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	decision := s.roleDecision(session.Role)
	if decision.Kind == roleSuperAdmin || decision.Kind == roleAdmin {
		return true
	}
	if decision.Kind == roleAuditor && auditorMayAccess(r) {
		return true
	}
	if customPermissionAllows(decision.Permissions, r) {
		return true
	}
	writeError(w, http.StatusForbidden, "permission denied")
	return false
}

func isAlwaysAllowedAuthenticatedAPI(r *http.Request) bool {
	path := strings.TrimRight(r.URL.Path, "/")
	if path == "/api/bootstrap" || path == "/api/auth/me" || path == "/api/auth/logout" {
		return true
	}
	if strings.HasPrefix(path, "/api/access/") {
		return true
	}
	return false
}

func auditorMayAccess(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	path := strings.TrimRight(r.URL.Path, "/")
	return path == "/api/system/monitoring" ||
		path == "/api/bootstrap" ||
		path == "/api/audit" ||
		strings.HasPrefix(path, "/api/admin/audit/")
}

func (s *Server) isAdminRequest(r *http.Request) bool {
	_, session, ok := s.auth.session(r)
	if !ok {
		return false
	}
	kind := s.roleDecision(session.Role).Kind
	return kind == roleSuperAdmin || kind == roleAdmin
}

func (s *Server) roleDecision(rawRole string) roleDecision {
	kind := normalizeBuiltInRole(rawRole)
	if kind != roleCustom {
		return roleDecision{Kind: kind}
	}
	roles, err := s.cfg.Store.ListPlatformItems("roles")
	if err != nil {
		return roleDecision{Kind: roleUser}
	}
	roleKey := strings.TrimSpace(rawRole)
	for _, role := range roles {
		if !roleMatches(role, roleKey) {
			continue
		}
		kind = normalizeBuiltInRole(role.Type)
		if kind == roleCustom {
			kind = normalizeBuiltInRole(role.Name)
		}
		if kind == roleCustom {
			kind = roleCustom
		}
		return roleDecision{Kind: kind, Permissions: roleAPIPermissions(role)}
	}
	return roleDecision{Kind: roleUser}
}

func normalizeBuiltInRole(rawRole string) roleKind {
	value := strings.ToLower(strings.TrimSpace(rawRole))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	switch value {
	case "super_admin", "superadmin", "root", "owner", "超级管理员", "瓒呯骇绠＄悊鍛":
		return roleSuperAdmin
	case "admin", "administrator", "管理员", "绠＄悊鍛":
		return roleAdmin
	case "auditor", "audit", "审计员", "瀹¤鍛":
		return roleAuditor
	case "user", "member", "普通用户", "鏅€氱敤鎴":
		return roleUser
	default:
		return roleCustom
	}
}

func roleMatches(role model.PlatformItem, roleKey string) bool {
	if roleKey == "" {
		return false
	}
	return role.ID == roleKey ||
		strings.EqualFold(role.Name, roleKey) ||
		strings.EqualFold(role.Type, roleKey)
}

func roleAPIPermissions(role model.PlatformItem) []string {
	permissions := []string{}
	for key, enabled := range role.Permissions {
		if enabled {
			permissions = append(permissions, key)
		}
	}
	for _, key := range []string{"api_permissions", "apiPermissions", "apis"} {
		permissions = append(permissions, stringListFromMetadata(role.Metadata[key])...)
	}
	return permissions
}

func stringListFromMetadata(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		items := []string{}
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				items = append(items, text)
			}
		}
		return items
	case string:
		parts := strings.FieldsFunc(typed, func(r rune) bool {
			return r == ',' || r == '\n' || r == ';'
		})
		items := []string{}
		for _, item := range parts {
			if strings.TrimSpace(item) != "" {
				items = append(items, strings.TrimSpace(item))
			}
		}
		return items
	default:
		return nil
	}
}

func customPermissionAllows(permissions []string, r *http.Request) bool {
	if len(permissions) == 0 {
		return false
	}
	method := strings.ToUpper(r.Method)
	path := strings.TrimRight(r.URL.Path, "/")
	for _, permission := range permissions {
		if permissionMatchesAPI(permission, method, path) {
			return true
		}
	}
	return false
}

func permissionMatchesAPI(permission, method, path string) bool {
	permission = strings.TrimSpace(permission)
	if permission == "" {
		return false
	}
	if permission == "admin:*" || permission == "* /api/*" || permission == "*" {
		return true
	}
	if permission == "audit:read" && method == http.MethodGet && strings.HasPrefix(path, "/api/admin/audit/") {
		return true
	}
	parts := strings.Fields(permission)
	if len(parts) == 1 {
		return pathMatches(parts[0], path)
	}
	return (parts[0] == "*" || strings.EqualFold(parts[0], method)) && pathMatches(parts[1], path)
}

func pathMatches(pattern, path string) bool {
	pattern = strings.TrimRight(pattern, "/")
	path = strings.TrimRight(path, "/")
	if pattern == path {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "/*")+"/")
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))
	}
	return false
}
