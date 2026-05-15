import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { getUser, updateUser } from '../services/user-service.js';
import { listUserRoles, assignRoleToUser, unassignRoleFromUser, listRoles } from '../services/role-service.js';
import { listUserGroups, assignGroupToUser, unassignGroupFromUser, listGroups } from '../services/group-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';

const ConfirmDialog = customElements.get('c-modal');

class UserDetailPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      user: null,
      savedUser: null,
      loading: true,
      saving: false,
      dirty: false,
      userRoles: [],
      userGroups: [],
      rolesLoading: false,
      groupsLoading: false,
      showAddRoleModal: false,
      showAddGroupModal: false,
      availableRoles: [],
      availableGroups: [],
      addRoleLoading: false,
      addGroupLoading: false,
    };
    this._onBeforeUnload = this._onBeforeUnload.bind(this);
  }

  connectedCallback() {
    super.connectedCallback();
    if (this.params && this.params.id) {
      this._loadUser(this.params.id);
    }
    window.addEventListener('beforeunload', this._onBeforeUnload);
  }

  disconnectedCallback() {
    window.removeEventListener('beforeunload', this._onBeforeUnload);
  }

  _onBeforeUnload(e) {
    if (this._state.dirty) {
      e.preventDefault();
      e.returnValue = '';
    }
  }

  get _isDirty() {
    const { user, savedUser } = this._state;
    if (!user || !savedUser) return false;
    return (
      user.email !== savedUser.email ||
      user.email_verified !== savedUser.email_verified ||
      user.username !== savedUser.username ||
      user.given_name !== savedUser.given_name ||
      user.family_name !== savedUser.family_name ||
      user.middle_name !== savedUser.middle_name ||
      user.nickname !== savedUser.nickname ||
      user.preferred_username !== savedUser.preferred_username ||
      user.profile !== savedUser.profile ||
      user.picture !== savedUser.picture ||
      user.website !== savedUser.website ||
      user.gender !== savedUser.gender ||
      user.birthdate !== savedUser.birthdate ||
      user.zoneinfo !== savedUser.zoneinfo ||
      user.phone_number !== savedUser.phone_number ||
      user.phone_number_verified !== savedUser.phone_number_verified ||
      user.street_address !== savedUser.street_address ||
      user.locality !== savedUser.locality ||
      user.region !== savedUser.region ||
      user.postal_code !== savedUser.postal_code ||
      user.country !== savedUser.country ||
      user.locale !== savedUser.locale ||
      user.enabled !== savedUser.enabled
    );
  }

  async _loadUser(id) {
    this.setState({ loading: true });
    try {
      const user = await getUser(id, this.signal);
      this.setState({ user, savedUser: { ...user }, loading: false, dirty: false });
      this._loadUserRoles(id);
      this._loadUserGroups(id);
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load user');
      this.setState({ loading: false });
    }
  }

  async _save() {
    const user = this._state.user;
    if (!user) return;
    this.setState({ saving: true });
    try {
      await updateUser(user.id, {
        email: user.email,
        email_verified: user.email_verified,
        username: user.username,
        given_name: user.given_name,
        family_name: user.family_name,
        middle_name: user.middle_name,
        nickname: user.nickname,
        preferred_username: user.preferred_username,
        profile: user.profile,
        picture: user.picture,
        website: user.website,
        gender: user.gender,
        birthdate: user.birthdate,
        zoneinfo: user.zoneinfo,
        phone_number: user.phone_number,
        phone_number_verified: user.phone_number_verified,
        street_address: user.street_address,
        locality: user.locality,
        region: user.region,
        postal_code: user.postal_code,
        country: user.country,
        locale: user.locale,
        enabled: user.enabled,
      });
      showToast('User updated', 'success');
      this.setState({ saving: false, savedUser: { ...user }, dirty: false });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to update user');
      this.setState({ saving: false });
    }
  }

  _updateField(field, value) {
    const user = { ...this._state.user, [field]: value };
    const savedUser = this._state.savedUser;
    const dirty = (
      user.email !== savedUser.email ||
      user.email_verified !== savedUser.email_verified ||
      user.username !== savedUser.username ||
      user.given_name !== savedUser.given_name ||
      user.family_name !== savedUser.family_name ||
      user.middle_name !== savedUser.middle_name ||
      user.nickname !== savedUser.nickname ||
      user.preferred_username !== savedUser.preferred_username ||
      user.profile !== savedUser.profile ||
      user.picture !== savedUser.picture ||
      user.website !== savedUser.website ||
      user.gender !== savedUser.gender ||
      user.birthdate !== savedUser.birthdate ||
      user.zoneinfo !== savedUser.zoneinfo ||
      user.phone_number !== savedUser.phone_number ||
      user.phone_number_verified !== savedUser.phone_number_verified ||
      user.street_address !== savedUser.street_address ||
      user.locality !== savedUser.locality ||
      user.region !== savedUser.region ||
      user.postal_code !== savedUser.postal_code ||
      user.country !== savedUser.country ||
      user.locale !== savedUser.locale ||
      user.enabled !== savedUser.enabled
    );
    this.setState({ user, dirty });
  }

  async _navigateAway(path) {
    if (this._state.dirty) {
      const confirmed = await ConfirmDialog.confirm('You have unsaved changes. Are you sure you want to leave?', 'Unsaved Changes');
      if (!confirmed) return;
    }
    // Remove beforeunload before navigating so it doesn't trigger
    this.setState({ dirty: false });
    navigate(path);
  }

  // --- Roles Section ---

  async _loadUserRoles(userId) {
    this.setState({ rolesLoading: true });
    try {
      const data = await listUserRoles(userId);
      this.setState({ userRoles: data.items || data || [], rolesLoading: false });
    } catch (err) {
      this.setState({ userRoles: [], rolesLoading: false });
    }
  }

  _openAddRoleModal() {
    this.setState({ showAddRoleModal: true, addRoleLoading: false });
    requestAnimationFrame(() => {
      const modal = this.shadowRoot.querySelector('c-modal.add-role-modal');
      if (modal) modal.open();
    });
    this._loadAvailableRoles();
  }

  _closeAddRoleModal() {
    const modal = this.shadowRoot.querySelector('c-modal.add-role-modal');
    if (modal) modal.close();
    this.setState({ showAddRoleModal: false });
  }

  async _loadAvailableRoles() {
    try {
      const data = await listRoles({ limit: '100' });
      const allRoles = data.items || [];
      const assignedIds = new Set((this._state.userRoles || []).map(r => r.id));
      const available = allRoles.filter(r => !assignedIds.has(r.id));
      this.setState({ availableRoles: available });
    } catch (err) {
      this.setState({ availableRoles: [] });
    }
  }

  async _addRole(roleId) {
    const user = this._state.user;
    if (!user || !roleId) return;
    this.setState({ addRoleLoading: true });
    try {
      await assignRoleToUser(user.id, roleId);
      showToast('Role assigned', 'success');
      this._closeAddRoleModal();
      this._loadUserRoles(user.id);
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to assign role');
      this.setState({ addRoleLoading: false });
    }
  }

  async _removeRole(roleId) {
    const user = this._state.user;
    if (!user) return;
    try {
      await unassignRoleFromUser(user.id, roleId);
      showToast('Role removed', 'success');
      this._loadUserRoles(user.id);
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to remove role');
    }
  }

  // --- Groups Section ---

  async _loadUserGroups(userId) {
    this.setState({ groupsLoading: true });
    try {
      const data = await listUserGroups(userId);
      this.setState({ userGroups: data.items || data || [], groupsLoading: false });
    } catch (err) {
      this.setState({ userGroups: [], groupsLoading: false });
    }
  }

  _openAddGroupModal() {
    this.setState({ showAddGroupModal: true, addGroupLoading: false });
    requestAnimationFrame(() => {
      const modal = this.shadowRoot.querySelector('c-modal.add-group-modal');
      if (modal) modal.open();
    });
    this._loadAvailableGroups();
  }

  _closeAddGroupModal() {
    const modal = this.shadowRoot.querySelector('c-modal.add-group-modal');
    if (modal) modal.close();
    this.setState({ showAddGroupModal: false });
  }

  async _loadAvailableGroups() {
    try {
      const data = await listGroups({ limit: '100' });
      const allGroups = data.items || [];
      const assignedIds = new Set((this._state.userGroups || []).map(g => g.id));
      const available = allGroups.filter(g => !assignedIds.has(g.id));
      this.setState({ availableGroups: available });
    } catch (err) {
      this.setState({ availableGroups: [] });
    }
  }

  async _addGroup(groupId) {
    const user = this._state.user;
    if (!user || !groupId) return;
    this.setState({ addGroupLoading: true });
    try {
      await assignGroupToUser(user.id, groupId);
      showToast('Group assigned', 'success');
      this._closeAddGroupModal();
      this._loadUserGroups(user.id);
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to assign group');
      this.setState({ addGroupLoading: false });
    }
  }

  async _removeGroup(groupId) {
    const user = this._state.user;
    if (!user) return;
    try {
      await unassignGroupFromUser(user.id, groupId);
      showToast('Group removed', 'success');
      this._loadUserGroups(user.id);
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to remove group');
    }
  }

  template() {
    const { user, loading, saving, dirty } = this._state;
    return html`
      <style>
        :host { display: block; }
        .back-link {
          display: inline-flex;
          align-items: center;
          gap: 0.25rem;
          color: var(--color-primary);
          text-decoration: none;
          font-size: 0.875rem;
          margin-bottom: 1rem;
          cursor: pointer;
        }
        .dirty-indicator {
          display: inline-block;
          width: 0.5rem;
          height: 0.5rem;
          border-radius: 50%;
          background: var(--color-warning, #f59e0b);
          margin-left: 0.5rem;
          vertical-align: middle;
        }
        .form { max-width: 32rem; }
        .field { margin-bottom: 1rem; }
        .field-label {
          display: block;
          font-size: 0.875rem;
          font-weight: 500;
          margin-bottom: 0.25rem;
        }
        .field-input, .field-textarea {
          width: 100%;
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          font-family: inherit;
          box-sizing: border-box;
        }
        .field-input:focus, .field-textarea:focus {
          outline: none;
          border-color: var(--color-primary);
        }
        .field-textarea {
          resize: vertical;
          min-height: 4rem;
        }
        .checkbox-row {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          margin-bottom: 1rem;
        }
        .actions { display: flex; gap: 0.5rem; margin-top: 1.5rem; }
        .section {
          margin-top: 2rem;
          padding-top: 1.5rem;
          border-top: 1px solid #e2e8f0;
        }
        .section-title {
          font-size: 1rem;
          font-weight: 600;
          margin-bottom: 1rem;
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        .item-list {
          list-style: none;
          padding: 0;
          margin: 0;
        }
        .item-list li {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0.5rem 0.75rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          margin-bottom: 0.375rem;
          font-size: 0.875rem;
        }
        .item-list li .item-name {
          font-weight: 500;
        }
        .item-list li .item-desc {
          color: var(--color-text-muted);
          margin-left: 0.5rem;
        }
        .empty-state {
          color: var(--color-text-muted);
          font-size: 0.875rem;
          padding: 0.5rem 0;
        }
        .field-select {
          width: 100%;
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          font-family: inherit;
          box-sizing: border-box;
        }
        .field-select:focus {
          outline: none;
          border-color: var(--color-primary);
        }
      </style>
      <c-page-layout title="User Details">
        <span class="back-link" @click=${() => this._navigateAway('/users')}>
          &larr; Back to Users
        </span>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : user
          ? html`
                <div class="form">
                  <div class="field">
                    <label class="field-label">Email</label>
                    <input class="field-input" type="email" .value=${user.email} @input=${(e) => this._updateField('email', e.target.value)} />
                  </div>
                  <div class="field">
                    <label class="field-label">Username</label>
                    <input class="field-input" type="text" .value=${user.username || ''} @input=${(e) => this._updateField('username', e.target.value)} />
                  </div>
                  <label class="checkbox-row">
                    <input type="checkbox" ?checked=${user.email_verified} @change=${(e) => this._updateField('email_verified', e.target.checked)} />
                    Email verified
                  </label>

                  <div class="section">
                    <div class="section-title">Personal Information</div>
                    <div class="field">
                      <label class="field-label">First Name</label>
                      <input class="field-input" type="text" .value=${user.given_name || ''} @input=${(e) => this._updateField('given_name', e.target.value)} />
                    </div>
                    <div class="field">
                      <label class="field-label">Last Name</label>
                      <input class="field-input" type="text" .value=${user.family_name || ''} @input=${(e) => this._updateField('family_name', e.target.value)} />
                    </div>
                    <div class="field">
                      <label class="field-label">Middle Name</label>
                      <input class="field-input" type="text" .value=${user.middle_name || ''} @input=${(e) => this._updateField('middle_name', e.target.value)} />
                    </div>
                    <div class="field">
                      <label class="field-label">Nickname</label>
                      <input class="field-input" type="text" .value=${user.nickname || ''} @input=${(e) => this._updateField('nickname', e.target.value)} />
                    </div>
                    <div class="field">
                      <label class="field-label">Preferred Username</label>
                      <input class="field-input" type="text" .value=${user.preferred_username || ''} @input=${(e) => this._updateField('preferred_username', e.target.value)} />
                    </div>
                    <div class="field">
                      <label class="field-label">Gender</label>
                      <input class="field-input" type="text" .value=${user.gender || ''} @input=${(e) => this._updateField('gender', e.target.value)} />
                    </div>
                    <div class="field">
                      <label class="field-label">Birthdate</label>
                      <input class="field-input" type="date" .value=${user.birthdate || ''} @input=${(e) => this._updateField('birthdate', e.target.value)} />
                    </div>
                  </div>

                  <div class="section">
                    <div class="section-title">Profile</div>
                    <div class="field">
                      <label class="field-label">Profile URL</label>
                      <input class="field-input" type="url" .value=${user.profile || ''} @input=${(e) => this._updateField('profile', e.target.value)} />
                    </div>
                    <div class="field">
                      <label class="field-label">Picture URL</label>
                      <input class="field-input" type="url" .value=${user.picture || ''} @input=${(e) => this._updateField('picture', e.target.value)} />
                    </div>
                    <div class="field">
                      <label class="field-label">Website URL</label>
                      <input class="field-input" type="url" .value=${user.website || ''} @input=${(e) => this._updateField('website', e.target.value)} />
                    </div>
                  </div>

                  <div class="section">
                    <div class="section-title">Contact</div>
                    <div class="field">
                      <label class="field-label">Phone Number</label>
                      <input class="field-input" type="tel" .value=${user.phone_number || ''} @input=${(e) => this._updateField('phone_number', e.target.value)} />
                    </div>
                    <label class="checkbox-row">
                      <input type="checkbox" ?checked=${user.phone_number_verified || false} @change=${(e) => this._updateField('phone_number_verified', e.target.checked)} />
                      Phone verified
                    </label>
                  </div>

                  <div class="section">
                    <div class="section-title">Address</div>
                    <div class="field">
                      <label class="field-label">Street Address</label>
                      <textarea class="field-textarea" .value=${user.street_address || ''} @input=${(e) => this._updateField('street_address', e.target.value)}></textarea>
                    </div>
                    <div class="field">
                      <label class="field-label">City / Locality</label>
                      <input class="field-input" type="text" .value=${user.locality || ''} @input=${(e) => this._updateField('locality', e.target.value)} />
                    </div>
                    <div class="field">
                      <label class="field-label">Region / State</label>
                      <input class="field-input" type="text" .value=${user.region || ''} @input=${(e) => this._updateField('region', e.target.value)} />
                    </div>
                    <div class="field">
                      <label class="field-label">Postal Code</label>
                      <input class="field-input" type="text" .value=${user.postal_code || ''} @input=${(e) => this._updateField('postal_code', e.target.value)} />
                    </div>
                    <div class="field">
                      <label class="field-label">Country (ISO 3166-1 alpha-2)</label>
                      <input class="field-input" type="text" .value=${user.country || ''} @input=${(e) => this._updateField('country', e.target.value)} placeholder="e.g. US, FR, DE" />
                    </div>
                  </div>

                  <div class="section">
                    <div class="section-title">Preferences</div>
                    <div class="field">
                      <label class="field-label">Locale</label>
                      <input class="field-input" type="text" .value=${user.locale || 'en'} @input=${(e) => this._updateField('locale', e.target.value)} placeholder="e.g. en, fr" />
                    </div>
                    <div class="field">
                      <label class="field-label">Timezone (IANA)</label>
                      <input class="field-input" type="text" .value=${user.zoneinfo || ''} @input=${(e) => this._updateField('zoneinfo', e.target.value)} placeholder="e.g. Europe/Paris" />
                    </div>
                  </div>

                  <label class="checkbox-row">
                    <input type="checkbox" ?checked=${user.enabled} @change=${(e) => this._updateField('enabled', e.target.checked)} />
                    Enabled
                  </label>

                  <!-- Roles Section -->
                  <div class="section">
                    <div class="section-title">
                      Roles
                      <c-button size="sm" variant="secondary" @click=${() => this._openAddRoleModal()}>+ Add Role</c-button>
                    </div>
                    ${this._state.rolesLoading
              ? html`<div class="empty-state">Loading...</div>`
              : this._state.userRoles.length > 0
                ? html`
                          <ul class="item-list">
                            ${this._state.userRoles.map(role => html`
                              <li>
                                <span>
                                  <span class="item-name">${role.name}</span>
                                  ${role.description ? html`<span class="item-desc">${role.description}</span>` : ''}
                                </span>
                                <c-button size="sm" variant="danger" @click=${() => this._removeRole(role.id)}>Remove</c-button>
                              </li>
                            `)}
                          </ul>
                        `
                : html`<div class="empty-state">No roles assigned.</div>`}
                  </div>

                  <!-- Groups Section -->
                  <div class="section">
                    <div class="section-title">
                      Groups
                      <c-button size="sm" variant="secondary" @click=${() => this._openAddGroupModal()}>+ Add Group</c-button>
                    </div>
                    ${this._state.groupsLoading
              ? html`<div class="empty-state">Loading...</div>`
              : this._state.userGroups.length > 0
                ? html`
                          <ul class="item-list">
                            ${this._state.userGroups.map(group => html`
                              <li>
                                <span>
                                  <span class="item-name">${group.name}</span>
                                  ${group.description ? html`<span class="item-desc">${group.description}</span>` : ''}
                                </span>
                                <c-button size="sm" variant="danger" @click=${() => this._removeGroup(group.id)}>Remove</c-button>
                              </li>
                            `)}
                          </ul>
                        `
                : html`<div class="empty-state">No groups assigned.</div>`}
                  </div>

                  <div class="actions">
                    <c-button variant="primary" ?disabled=${saving || !dirty} @click=${() => this._save()}>
                      ${saving ? 'Saving...' : 'Save Changes'}${dirty ? html`<span class="dirty-indicator"></span>` : ''}
                    </c-button>
                    <c-button variant="ghost" @click=${() => this._navigateAway('/users')}>Cancel</c-button>
                  </div>
                </div>
              `
          : html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">User not found.</div>`}
      </c-page-layout>

      <c-modal title="Add Role to User" class="add-role-modal" @close=${() => this._closeAddRoleModal()}>
        ${this._state.showAddRoleModal ? html`
          <div class="form">
            <div class="field">
              <label class="field-label">Select Role</label>
              <select class="field-select" id="role-select">
                <option value="">-- Select a role --</option>
                ${this._state.availableRoles.map(r => html`<option value=${r.id}>${r.name}${r.description ? ` - ${r.description}` : ''}</option>`)}
              </select>
            </div>
          </div>
        ` : ''}
        <div slot="footer">
          <c-button variant="secondary" @click=${() => this._closeAddRoleModal()}>Cancel</c-button>
          <c-button variant="primary" ?disabled=${this._state.addRoleLoading} @click=${() => {
        const select = this.shadowRoot.getElementById('role-select');
        if (select && select.value) this._addRole(select.value);
      }}>
            ${this._state.addRoleLoading ? 'Adding...' : 'Add Role'}
          </c-button>
        </div>
      </c-modal>

      <c-modal title="Add Group to User" class="add-group-modal" @close=${() => this._closeAddGroupModal()}>
        ${this._state.showAddGroupModal ? html`
          <div class="form">
            <div class="field">
              <label class="field-label">Select Group</label>
              <select class="field-select" id="group-select">
                <option value="">-- Select a group --</option>
                ${this._state.availableGroups.map(g => html`<option value=${g.id}>${g.name}${g.description ? ` - ${g.description}` : ''}</option>`)}
              </select>
            </div>
          </div>
        ` : ''}
        <div slot="footer">
          <c-button variant="secondary" @click=${() => this._closeAddGroupModal()}>Cancel</c-button>
          <c-button variant="primary" ?disabled=${this._state.addGroupLoading} @click=${() => {
        const select = this.shadowRoot.getElementById('group-select');
        if (select && select.value) this._addGroup(select.value);
      }}>
            ${this._state.addGroupLoading ? 'Adding...' : 'Add Group'}
          </c-button>
        </div>
      </c-modal>
    `;
  }
}

customElements.define('user-detail-page', UserDetailPage);
