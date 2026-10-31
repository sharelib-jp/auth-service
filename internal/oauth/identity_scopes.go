package oauth

// IdentityResource identifies claims supplied by this provider. It is distinct
// from business API resources and does not depend on the deployment hostname.
const IdentityResource = "urn:auth-service:identity"

// identityScope defines the claims that require a separately revocable grant.
// Increment PolicyVersion when the information shared by a scope changes.
func identityScope(name string) (Scope, bool) {
	var description string
	switch name {
	case "profile":
		description = "表示名とユーザー名"
	case "email":
		description = "メールアドレス"
	default:
		return Scope{}, false
	}
	return Scope{ResourceID: IdentityResource, Name: name, Description: description, PurposeCode: "oidc_userinfo", PolicyVersion: 1, Status: "active"}, true
}

// IdentityScope returns the display metadata for a supported identity scope.
func IdentityScope(name string) (Scope, bool) { return identityScope(name) }

// ConsentResource identifies the owner of the data requested by a scope.
func ConsentResource(scope Scope, business Resource) string {
	if scope.ResourceID == IdentityResource {
		return IdentityResource
	}
	return business.Identifier
}
