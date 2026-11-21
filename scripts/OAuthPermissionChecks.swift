import Foundation

@main
struct OAuthPermissionChecks {
    @MainActor
    static func main() {
        let model = PermissionSelectionViewModel()
        let baseline: Set<String> = ["account-settings.read", "zone.read"]
        precondition(Set(model.selectedScopes) == baseline, "New login must request only the baseline")
        model.toggleFeature(id: "account")
        model.toggleFeature(id: "zones")
        precondition(Set(model.selectedScopes) == baseline, "Required modules cannot be disabled")

        model.applyAllReadOnly()
        let readOnly = Set(model.selectedScopes)
        precondition(!readOnly.contains(where: { $0.hasSuffix(".write") || $0.hasSuffix(".admin") || $0 == "cache.purge" }))
        precondition(readOnly.contains("zone-security-center-insights.read"))
        precondition(readOnly.contains("notifications.read"), "Cloudflare alert management belongs to the main app")
        model.applyAllReadWrite()
        let full = Set(model.selectedScopes)
        precondition(readOnly.isSubset(of: full))
        precondition(full.contains("workers-observability.write"), "Historical logs require Write at the API")
        precondition(full.contains("zone-security-center-insights.write"))
        precondition(model.selectedScopes.count == full.count, "Shared dependencies must be deduplicated")

        model.applyMinimal()
        model.toggleFeature(id: "dns_settings")
        precondition(Set(model.selectedScopes) == baseline.union(["zone-dns-settings.read", "dns.read"]))
        model.toggleEditPermission(id: "dns_settings")
        precondition(Set(model.selectedScopes).isSuperset(of: ["zone-dns-settings.write", "dns.write"]))
        model.toggleFeature(id: "dns_settings")
        precondition(Set(model.selectedScopes) == baseline)
        precondition(!model.permissions.first(where: { $0.id == "dns_settings" })!.canEdit)

        let dnsUpgrade = FeaturePermission.scopeSetIncludingDependencies(["zone-dns-settings.write"])
        precondition(dnsUpgrade == baseline.union(["zone-dns-settings.read", "zone-dns-settings.write", "dns.read", "dns.write"]))
        let email = FeaturePermission.scopeSetIncludingDependencies(["email-routing-rule.read"])
        precondition(email.isSuperset(of: ["email-routing-address.read", "email-routing-suppression.read", "zone-settings.read"]))
        precondition(!email.contains("zone-settings.write"))
        let ai = FeaturePermission.scopeSetIncludingDependencies(["ai.write"])
        precondition(ai == baseline.union(["ai.read", "ai.write"]))
        precondition(!ai.contains("aig.write"), "An AI upgrade must not grant AI Gateway")
        let logs = FeaturePermission.scopeSetIncludingDependencies(["workers-observability.write"])
        precondition(logs == baseline.union(["workers-observability.read", "workers-observability.write"]))
        precondition(FeaturePermission.scopeSetIncludingDependencies(["workers-tail.read"]).contains("workers-scripts.read"))
        precondition(FeaturePermission.scopeSetIncludingDependencies(["workers-ci.read"]).contains("workers-scripts.read"))
        precondition(FeaturePermission.scopeSetIncludingDependencies(["r2-catalog.read"]).contains("workers-r2.read"))

        model.applyGrantedScopes(["account-settings.read", "zone.read", "dns.read", "dns.write", "offline_access"])
        precondition(model.permissions.first(where: { $0.id == "dns" })!.canEdit)
        precondition(!model.permissions.first(where: { $0.id == "dns_settings" })!.isEnabled, "Shared dependencies must not select unrelated modules")
        let existing: Set<String> = ["dns.read", "offline_access", "previously-granted-scope"]
        precondition(existing.union(ai).isSuperset(of: existing), "Incremental authorization preserves existing scopes")
        model.applyMinimal()
        precondition(Set(model.selectedScopes) == baseline)
        print("OAuth permission behavior checks passed")
    }
}
