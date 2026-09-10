import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { navigate } from '../core/router.js';
import { listUsers } from '../services/user-service.js';
import { listIdentityProviders } from '../services/idp-service.js';
import { listGroups } from '../services/group-service.js';
import {
  addOrganizationDomain,
  addOrganizationMember,
  createOrganizationInvitation,
  deleteOrganizationDomain,
  verifyOrganizationDomain,
  getOrganization,
  linkOrganizationIdentityProvider,
  listOrganizationDomains,
  listOrganizationIdentityProviders,
  listOrganizationMembers,
  listOrganizationInvitations,
  removeOrganizationMember,
  revokeOrganizationInvitation,
  unlinkOrganizationIdentityProvider,
  updateOrganization,
  listOrganizationGroups, linkOrganizationGroup, unlinkOrganizationGroup,
} from '../services/organization-service.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';

class OrganizationDetailPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      organization: null, loading: true, saving: false, attributesText: '{}', claimAttributeNames: '',
      domains: [], domain: '', wildcard: false, verificationRecord: null,
      members: [], availableUsers: [], selectedUserId: '',
      providers: [], availableProviders: [], selectedProviderId: '', redirectOnDomain: false,
      invitations: [], invitationEmail: '', invitationFirstName: '', invitationLastName: '',
      groups: [], availableGroups: [], selectedGroupId: '',
    };
  }

  connectedCallback() {
    super.connectedCallback();
    if (this.params?.id) this._load(this.params.id);
  }

  async _load(id) {
    try {
      const organization = await getOrganization(id, this.signal);
      await this.setState({
        organization,
        attributesText: JSON.stringify(organization.attributes || {}, null, 2),
        claimAttributeNames: (organization.claim_attribute_names || []).join(', '),
        loading: false,
      });
      await Promise.all([
        this._loadDomains(), this._loadMembers(), this._loadProviders(), this._loadInvitations(), this._loadGroups(),
      ]);
    } catch (error) {
      if (error.name === 'AbortError') return;
      handleApiError(error, 'Failed to load organization');
      this.setState({ loading: false });
    }
  }

  async _loadDomains() {
    const data = await listOrganizationDomains(this.params.id, this.signal);
    this.setState({ domains: data.items || [] });
  }

  async _loadMembers() {
    const organization = this._state.organization;
    const [memberData, userData] = await Promise.all([
      listOrganizationMembers(this.params.id, this.signal),
      listUsers({ realm_id: organization.realm_id, limit: 100, offset: 0 }, this.signal),
    ]);
    const members = memberData.items || [];
    const memberIds = new Set(members.map((member) => member.user_id));
    this.setState({
      members,
      availableUsers: (userData.items || []).filter((user) => !memberIds.has(user.id)),
    });
  }

  async _loadProviders() {
    const organization = this._state.organization;
    const [linkData, providerData] = await Promise.all([
      listOrganizationIdentityProviders(this.params.id, this.signal),
      listIdentityProviders(organization.realm_id, this.signal),
    ]);
    const providers = linkData.items || [];
    const linkedIds = new Set(providers.map((provider) => provider.identity_provider_id));
    this.setState({
      providers,
      availableProviders: (providerData.items || providerData || [])
        .filter((provider) => !linkedIds.has(provider.id)),
    });
  }

  async _loadInvitations() {
    const data = await listOrganizationInvitations(this.params.id, this.signal);
    this.setState({ invitations: data.items || [] });
  }

  async _loadGroups() {
    const [linkData, groupData] = await Promise.all([
      listOrganizationGroups(this.params.id, this.signal),
      listGroups({ realm_id: this._state.organization.realm_id, limit: 100, offset: 0 }, this.signal),
    ]);
    const groups = linkData.items || [];
    const linked = new Set(groups.map((group) => group.group_id));
    this.setState({ groups, availableGroups: (groupData.items || []).filter((group) => !linked.has(group.id)) });
  }

  async _linkGroup() {
    if (!this._state.selectedGroupId) return;
    try {
      await linkOrganizationGroup(this.params.id, this._state.selectedGroupId);
      this.setState({ selectedGroupId: '' }); await this._loadGroups();
      showToast('Group linked', 'success');
    } catch (error) { handleApiError(error, 'Failed to link group'); }
  }

  _setOrganization(field, value) {
    this.setState({ organization: { ...this._state.organization, [field]: value } });
  }

  async _save() {
    let attributes;
    try {
      attributes = JSON.parse(this._state.attributesText || '{}');
      if (!attributes || Array.isArray(attributes) || typeof attributes !== 'object') throw new Error();
    } catch {
      showToast('Attributes must be a JSON object', 'error');
      return;
    }
    const organization = this._state.organization;
    this.setState({ saving: true });
    try {
      const updated = await updateOrganization(organization.id, {
        name: organization.name,
        alias: organization.alias,
        redirect_url: organization.redirect_url || '',
        enabled: organization.enabled,
        attributes,
        claim_attribute_names: this._state.claimAttributeNames.split(',').map((name) => name.trim()).filter(Boolean),
      });
      this.setState({ organization: updated, saving: false });
      showToast('Organization updated', 'success');
    } catch (error) {
      handleApiError(error, 'Failed to update organization');
      this.setState({ saving: false });
    }
  }

  async _addDomain() {
    if (!this._state.domain.trim()) return;
    try {
      const created = await addOrganizationDomain(this.params.id, {
        domain: this._state.domain.trim(), wildcard: this._state.wildcard,
      });
      this.setState({ domain: '', wildcard: false, verificationRecord: created.verification_record });
      await this._loadDomains();
      showToast('Domain added', 'success');
    } catch (error) { handleApiError(error, 'Failed to add domain'); }
  }

  async _addMember() {
    if (!this._state.selectedUserId) return;
    try {
      await addOrganizationMember(this.params.id, {
        user_id: this._state.selectedUserId,
      });
      this.setState({ selectedUserId: '' });
      await this._loadMembers();
      showToast('Member added', 'success');
    } catch (error) { handleApiError(error, 'Failed to add member'); }
  }

  async _linkProvider() {
    if (!this._state.selectedProviderId) return;
    try {
      await linkOrganizationIdentityProvider(this.params.id, {
        identity_provider_id: this._state.selectedProviderId,
        redirect_on_email_domain: this._state.redirectOnDomain,
      });
      this.setState({ selectedProviderId: '', redirectOnDomain: false });
      await this._loadProviders();
      showToast('Identity provider linked', 'success');
    } catch (error) { handleApiError(error, 'Failed to link identity provider'); }
  }

  async _inviteMember() {
    if (!this._state.invitationEmail.trim()) return;
    try {
      await createOrganizationInvitation(this.params.id, {
        email: this._state.invitationEmail.trim(),
        first_name: this._state.invitationFirstName.trim() || null,
        last_name: this._state.invitationLastName.trim() || null,
      });
      this.setState({ invitationEmail: '', invitationFirstName: '', invitationLastName: '' });
      await this._loadInvitations();
      showToast('Invitation created', 'success');
    } catch (error) { handleApiError(error, 'Failed to create invitation'); }
  }

  async _revokeInvitation(invitationId) {
    try {
      await revokeOrganizationInvitation(this.params.id, invitationId);
      await this._loadInvitations();
      showToast('Invitation revoked', 'success');
    } catch (error) { handleApiError(error, 'Failed to revoke invitation'); }
  }

  template() {
    const s = this._state;
    const organization = s.organization;
    return html`<c-page-layout title="Organization Details">
      <button class="back-link" @click=${() => navigate('/organizations')}>&larr; Back to Organizations</button>
      ${s.loading ? html`<div class="empty-state">Loading...</div>` : !organization
        ? html`<div class="empty-state">Organization not found.</div>`
        : html`
          <div class="section"><div class="section-title">Settings</div>
            <div class="form">
              <div class="field"><label class="field-label">Name</label>
                <input class="field-input" .value=${organization.name}
                  @input=${(e) => this._setOrganization('name', e.target.value)} /></div>
              <div class="field"><label class="field-label">Alias</label>
                <input class="field-input" .value=${organization.alias} readonly /></div>
              <div class="field"><label class="field-label">Redirect URL after invitation acceptance</label>
                <input class="field-input" type="url" placeholder="https://app.example.com/welcome"
                  .value=${organization.redirect_url || ''}
                  @input=${(e) => this._setOrganization('redirect_url', e.target.value)} /></div>
              <label class="checkbox-row"><input type="checkbox" ?checked=${organization.enabled}
                @change=${(e) => this._setOrganization('enabled', e.target.checked)} /> Enabled</label>
              <div class="field"><label class="field-label">Attributes (JSON object)</label>
                <textarea class="field-input" rows="6" .value=${s.attributesText}
                  @input=${(e) => this.setState({ attributesText: e.target.value })}></textarea></div>
              <div class="field"><label class="field-label">Attributes exposed in tokens</label>
                <input class="field-input" placeholder="plan, region" .value=${s.claimAttributeNames}
                  @input=${(e) => this.setState({ claimAttributeNames: e.target.value })} />
                <div class="hint">Comma-separated attribute names. Unlisted attributes remain admin-only.</div></div>
              <c-button variant="primary" ?disabled=${s.saving} @click=${() => this._save()}>
                ${s.saving ? 'Saving...' : 'Save Changes'}
              </c-button>
            </div>
          </div>

          <div class="section"><div class="section-title">Email domains</div>
            <div class="toolbar"><input class="field-input" placeholder="example.com" .value=${s.domain}
              @input=${(e) => this.setState({ domain: e.target.value })} />
              <label class="checkbox-row"><input type="checkbox" ?checked=${s.wildcard}
                @change=${(e) => this.setState({ wildcard: e.target.checked })} /> Include subdomains</label>
              <c-button @click=${() => this._addDomain()}>Add Domain</c-button></div>
            ${s.verificationRecord ? html`<div class="empty-state"><strong>Add this DNS TXT record, then verify:</strong>
              <div><code>${s.verificationRecord.name}</code></div><div><code>${s.verificationRecord.value}</code></div></div>` : ''}
            ${s.domains.length ? html`<ul>${s.domains.map((domain) => html`<li>
              ${domain.kind === 'wildcard' ? '*.' : ''}${domain.domain}
              ${domain.verified ? '(verified)' : '(unverified)'}
              ${!domain.verified ? html`<c-button size="sm" @click=${async () => {
                await verifyOrganizationDomain(this.params.id, domain.id); this._loadDomains();
              }}>Verify DNS</c-button>` : ''}
              <c-button size="sm" variant="danger" @click=${async () => {
                await deleteOrganizationDomain(this.params.id, domain.id);
                this._loadDomains();
              }}>Remove</c-button></li>`)}</ul>` : html`<p>No domains configured.</p>`}
          </div>

          <div class="section"><div class="section-title">Members</div>
            <div class="toolbar"><select class="field-select" .value=${s.selectedUserId}
              @change=${(e) => this.setState({ selectedUserId: e.target.value })}>
              <option value="">Select a realm user</option>${s.availableUsers.map((user) => html`
                <option value=${user.id}>${user.email}</option>`)}</select>
              <c-button @click=${() => this._addMember()}>Add Member</c-button></div>
            ${s.members.length ? html`<c-table .columns=${[
              { key: 'email', label: 'Email' }, { key: 'kind', label: 'Lifecycle' },
              { key: 'user_id', label: 'Actions', render: (_, member) => html`<c-button size="sm" variant="danger"
                @click=${async () => { await removeOrganizationMember(this.params.id, member.user_id); this._loadMembers(); }}>Remove</c-button>` },
            ]} .rows=${s.members}></c-table>` : html`<p>No members.</p>`}
          </div>

          <div class="section"><div class="section-title">Invitations</div>
            <div class="toolbar">
              <input class="field-input" type="email" placeholder="person@example.com"
                .value=${s.invitationEmail}
                @input=${(e) => this.setState({ invitationEmail: e.target.value })} />
              <input class="field-input" placeholder="First name" .value=${s.invitationFirstName}
                @input=${(e) => this.setState({ invitationFirstName: e.target.value })} />
              <input class="field-input" placeholder="Last name" .value=${s.invitationLastName}
                @input=${(e) => this.setState({ invitationLastName: e.target.value })} />
              <c-button @click=${() => this._inviteMember()}>Send Invitation</c-button>
            </div>
            ${s.invitations.length ? html`<c-table .columns=${[
              { key: 'email', label: 'Email' },
              { key: 'status', label: 'Status' },
              { key: 'expires_at', label: 'Expires', render: (value) => new Date(value).toLocaleString() },
              { key: 'id', label: 'Actions', render: (_, invitation) => invitation.status === 'pending'
                ? html`<c-button size="sm" variant="danger"
                    @click=${() => this._revokeInvitation(invitation.id)}>Revoke</c-button>`
                : '' },
            ]} .rows=${s.invitations}></c-table>` : html`<p>No invitations.</p>`}
          </div>

          <div class="section"><div class="section-title">Identity providers</div>
            <div class="toolbar"><select class="field-select" .value=${s.selectedProviderId}
              @change=${(e) => this.setState({ selectedProviderId: e.target.value })}>
              <option value="">Select a realm identity provider</option>${s.availableProviders.map((provider) => html`
                <option value=${provider.id}>${provider.display_name || provider.alias}</option>`)}</select>
              <label class="checkbox-row"><input type="checkbox" ?checked=${s.redirectOnDomain}
                @change=${(e) => this.setState({ redirectOnDomain: e.target.checked })} /> Redirect matching email domains</label>
              <c-button @click=${() => this._linkProvider()}>Link Provider</c-button></div>
            ${s.providers.length ? html`<ul>${s.providers.map((provider) => html`<li>
              ${provider.display_name} ${provider.redirect_on_email_domain ? '(domain redirect)' : ''}
              <c-button size="sm" variant="danger" @click=${async () => {
                await unlinkOrganizationIdentityProvider(this.params.id, provider.identity_provider_id);
                this._loadProviders();
              }}>Unlink</c-button></li>`)}</ul>` : html`<p>No identity providers linked.</p>`}
          </div>

          <div class="section"><div class="section-title">Organization groups</div>
            <p>Only memberships in these realm groups are emitted as organization groups and roles in tokens.</p>
            <div class="toolbar"><select class="field-select" .value=${s.selectedGroupId}
              @change=${(e) => this.setState({ selectedGroupId: e.target.value })}>
              <option value="">Select a realm group</option>${s.availableGroups.map((group) => html`
                <option value=${group.id}>${group.name}</option>`)}</select>
              <c-button @click=${() => this._linkGroup()}>Link Group</c-button></div>
            ${s.groups.length ? html`<ul>${s.groups.map((group) => html`<li>${group.name}
              <c-button size="sm" variant="danger" @click=${async () => {
                await unlinkOrganizationGroup(this.params.id, group.group_id); this._loadGroups();
              }}>Unlink</c-button></li>`)}</ul>` : html`<p>No organization groups linked.</p>`}
          </div>
        `}
    </c-page-layout>`;
  }
}

customElements.define('organization-detail-page', OrganizationDetailPage);
