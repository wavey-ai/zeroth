use leptos::prelude::*;

/// Provisioning uses separate admin forms so saving tenant metadata cannot
/// accidentally enable lifecycle enforcement or overwrite source credentials.
#[component]
pub(super) fn TenantProvisioningPanel() -> impl IntoView {
    view! {
        <section id="zeroth-provisioning" class="zeroth-provisioning">
            <div class="zeroth-panel-header">
                <div><h3 class="zeroth-panel-title">"5. Automatic provisioning and offboarding"</h3><p class="zeroth-section-description">"Keep tenant access aligned with the corporate directory. Sign-in and provisioning use separate credentials."</p></div>
                <button class="zeroth-action" id="zeroth-provisioning-refresh" type="button" disabled=true>"Refresh status"</button>
            </div>
            <div class="zeroth-panel-body zeroth-stack">
                <p class="zeroth-help" id="zeroth-provisioning-intro" role="status">"Save the tenant before configuring provisioning."</p>
                <p class="zeroth-provisioning-policy" id="zeroth-provisioning-policy" hidden=true></p>
                <div id="zeroth-scim-panel" hidden=true>
                    <h4>"Microsoft Entra · SCIM users"</h4>
                    <p class="zeroth-help">"Use the customer's own Entra tenant and enterprise application. A Wavey-owned Entra registration is needed only for a shared multi-tenant application operated by Wavey."</p>
                    <div class="zeroth-field"><label for="zeroth-scim-endpoint">"Tenant SCIM endpoint"</label><div class="zeroth-copy-field"><input id="zeroth-scim-endpoint" readonly=true /><button class="zeroth-action" id="zeroth-scim-copy" type="button">"Copy endpoint"</button></div><small>"Enter this URL in the customer's Entra provisioning configuration. Groups and group-to-role mapping are not supported."</small></div>
                    <dl id="zeroth-scim-status" class="zeroth-provisioning-status" aria-live="polite"></dl>
                    <form id="zeroth-scim-form" class="zeroth-form">
                        <div class="zeroth-field"><label for="zeroth-scim-binding">"SCIM token environment binding"</label><input id="zeroth-scim-binding" name="tokenBinding" autocomplete="off" spellcheck="false" maxlength="128" placeholder="TENANT_ACME_SCIM_TOKEN" /><small>"Binding name only. An operator stores the random token in the deployment and supplies the same token to Entra's Secret Token field. Zeroth never displays the token value."</small></div>
                        <label class="zeroth-checkbox-field"><input name="enabled" type="checkbox" />"Require active provisioned users for tenant access"</label>
                        <div class="zeroth-form-actions"><button class="zeroth-action zeroth-primary" type="submit">"Save SCIM settings"</button></div>
                    </form>
                    <p class="zeroth-help zeroth-provisioning-footnote">"Requiring provisioned users revokes existing tenant grants. Run initial provisioning before users sign in. Clearing this requirement permits unknown signed corporate identities; inactive tombstones still deny access. SCIM delivery uses its token binding independently."</p>
                </div>
                <div id="zeroth-google-directory-panel" hidden=true>
                    <h4>"Google Workspace · Directory sync"</h4>
                    <p class="zeroth-help">"Read users from the pinned Workspace customer using a service account with domain-wide delegation. Suspended, archived, and deleted members lose tenant access after their lifecycle update is applied."</p>
                    <dl id="zeroth-google-directory-status" class="zeroth-provisioning-status" aria-live="polite"></dl>
                    <form id="zeroth-google-directory-form" class="zeroth-form">
                        <div class="zeroth-settings-fields">
                            <div class="zeroth-field"><label for="zeroth-directory-customer">"Google Workspace customer ID"</label><input id="zeroth-directory-customer" name="customerId" autocomplete="off" placeholder="C01234567" /><small>"Use the exact customer ID, not a domain or my_customer. A verified directory cannot be silently reassigned."</small></div>
                            <div class="zeroth-field"><label for="zeroth-directory-admin">"Delegate super-admin email"</label><input id="zeroth-directory-admin" name="delegatedAdminEmail" type="email" autocomplete="off" placeholder="directory-admin@company.example" /><small>"An active, unarchived Workspace super administrator is required to verify full directory visibility."</small></div>
                            <div class="zeroth-field"><label for="zeroth-directory-binding">"Service-account JSON environment binding"</label><input id="zeroth-directory-binding" name="serviceAccountSecretBinding" autocomplete="off" spellcheck="false" maxlength="128" placeholder="TENANT_ACME_GOOGLE_DIRECTORY_SERVICE_ACCOUNT" /><small>"Binding name only. Store the full service-account JSON key in the deployment secret store, never in this form."</small></div>
                            <div class="zeroth-field"><label>"Delegated OAuth scope"</label><code class="zeroth-code zeroth-scope">"https://www.googleapis.com/auth/admin.directory.user.readonly"</code><small>"Grant this read-only scope to the service account's numeric client ID in Google Admin domain-wide delegation."</small></div>
                        </div>
                        <label class="zeroth-checkbox-field"><input name="enabled" type="checkbox" />"Enable automatic directory polling"</label>
                        <div class="zeroth-form-footer"><button class="zeroth-action" id="zeroth-directory-sync" type="button" disabled=true>"Sync directory now"</button><button class="zeroth-action zeroth-primary" type="submit">"Save Directory settings"</button></div>
                    </form>
                    <p class="zeroth-help zeroth-provisioning-footnote">"Only a complete, validated scan can reconcile missing members. Partial scans and errors do not bulk-deactivate users. After first activation, managed access stays enforced. Pausing polling blocks online access once the last completed sync is more than 15 minutes old."</p>
                </div>
                <p class="zeroth-help">"Local sessions and refresh credentials are revoked when an offboarding update is applied. Upstream delivery, polling, and already-issued access tokens add delay: offboarding is not instantaneous. Enterprise access tokens expire within five minutes."</p>
                <a href="/admin/setup#provisioning" target="_blank" rel="noopener">"Provisioning setup and verification guide ↗"</a>
            </div>
        </section>
    }
}
