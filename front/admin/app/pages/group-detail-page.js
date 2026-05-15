import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { getGroup, updateGroup, listGroupRoles, assignRoleToGroup, unassignRoleFromGroup } from '../services/group-service.js';
import { listRoles } from '../services/role-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';

class GroupDetailPage extends BaseComponent {
  constructor() {
    super();
    this._state = {
      group: null,
      savedGroup: null,
      loading: true,
      saving: false,
      dirty: false,
      groupRoles: [],
      groupMembers: [],
      rolesLoading: false,
      membersLoading: false,
      showAddRoleModal: false,
      availableRoles: [],
      addRoleLoading: false,
    };
    this._onBeforeUnload = this._onBeforeUnload.bind(this);
  }

  connectedCallback() {
    super.connectedCallback();
    if (this.params && this.params.id) {
      this._loadGroup(this.params.id);
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
    const { group, savedGroup } = this._state;
    if (!group || !savedGroup) return false;
    return (
      group.name !== savedGroup.name ||
      group.description !== savedGroup.description
    );
  }

  async _loadGroup(id) {
    this.setState({ loading: true });
    try {
      const group = await getGroup(id);
      this.setState({ group, savedGroup: { ...group }, loading: false, dirty: false });
      this._loadGroupRoles(id);
      this._loadGroupMembers(id);
    } catch (err) {
      showToast('Failed to load group', 'error');
      this.setState({ loading: false });
    }
  }

  async _loadGroupRoles(id) {
    this.setState({ rolesLoading: true });
    try {
      const data = await listGroupRoles(id);
      this.setState({ groupRoles: data.items || data || [], rolesLoading: false });
    } catch (err) {
      this.setState({ groupRoles: [], rolesLoading: false });
    }
  }

  async _loadGroupMembers(id) {
    this.setState({ membersLoading: true });
    try {
      // The group object may include members; if not, we leave it empty
      const group = this._state.group;
      this.setState({ groupMembers: group.members || [], membersLoading: false });
    } catch (err) {
      this.setState({ groupMembers: [], membersLoading: false });
    }
  }

  async _save() {
    const group = this._state.group;
    if (!group) return;
    this.setState({ saving: true });
    try {
      await updateGroup(group.id, {
        name: group.name,
        description: group.description,
      });
      showToast('Group updated', 'success');
      const savedGroup = { ...group };
      this.setState({ saving: false, savedGroup, dirty: false });
    } catch (err) {
      showToast('Failed to update group', 'error');
      this.setState({ saving: false });
    }
  }

  _updateField(field, value) {
    const group = { ...this._state.group, [field]: value };
    const savedGroup = this._state.savedGroup;
    const dirty = (
      group.name !== savedGroup.name ||
      group.description !== savedGroup.description
    );
    this.setState({ group, dirty });
  }

  _navigateAway(path) {
    if (this._state.dirty) {
      if (!confirm('You have unsaved changes. Are you sure you want to leave?')) {
        return;
      }
    }
    this.setState({ dirty: false });
    navigate(path);
  }

  _openAddRoleModal() {
    this.setState({ showAddRoleModal: true, addRoleLoading: false });
    requestAnimationFrame(() => {
      const modal = this.shadowRoot.querySelector('c-modal.add-role-modal');
      if (modal) modal.open();
    });
    // Load available roles
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
      // Filter out already-assigned roles
      const assignedIds = new Set((this._state.groupRoles || []).map(r => r.id));
      const available = allRoles.filter(r => !assignedIds.has(r.id));
      this.setState({ availableRoles: available });
    } catch (err) {
      this.setState({ availableRoles: [] });
    }
  }

  async _addRole(roleId) {
    const group = this._state.group;
    if (!group || !roleId) return;
    this.setState({ addRoleLoading: true });
    try {
      await assignRoleToGroup(group.id, roleId);
      showToast('Role assigned', 'success');
      this._closeAddRoleModal();
      this._loadGroupRoles(group.id);
    } catch (err) {
      showToast('Failed to assign role', 'error');
      this.setState({ addRoleLoading: false });
    }
  }

  async _removeRole(roleId) {
    const group = this._state.group;
    if (!group) return;
    try {
      await unassignRoleFromGroup(group.id, roleId);
      showToast('Role removed', 'success');
      this._loadGroupRoles(group.id);
    } catch (err) {
      showToast('Failed to remove role', 'error');
    }
  }

  template() {
    const { group, loading, saving, dirty, groupRoles, groupMembers, rolesLoading, showAddRoleModal, availableRoles, addRoleLoading } = this._state;
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
        .field-input {
          width: 100%;
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #e2e8f0;
          border-radius: var(--radius-sm);
          font-family: inherit;
          box-sizing: border-box;
        }
        .field-input:focus {
          outline: none;
          border-color: var(--color-primary);
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
        .section-actions {
          margin-bottom: 0.75rem;
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
      <c-page-layout title="Group Details">
        <span class="back-link" @click=${() => this._navigateAway('/groups')}>
          &larr; Back to Groups
        </span>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : group
          ? html`
                <div class="form">
                  <div class="field">
                    <label class="field-label">Name</label>
                    <input class="field-input" type="text" .value=${group.name || ''} @input=${(e) => this._updateField('name', e.target.value)} />
                  </div>
                  <div class="field">
                    <label class="field-label">Description</label>
                    <input class="field-input" type="text" .value=${group.description || ''} @input=${(e) => this._updateField('description', e.target.value)} />
                  </div>
                  <div class="actions">
                    <c-button variant="primary" ?disabled=${saving || !dirty} @click=${() => this._save()}>
                      ${saving ? 'Saving...' : 'Save Changes'}${dirty ? html`<span class="dirty-indicator"></span>` : ''}
                    </c-button>
                    <c-button variant="ghost" @click=${() => this._navigateAway('/groups')}>Cancel</c-button>
                  </div>
                </div>

                <!-- Assigned Roles Section -->
                <div class="section">
                  <div class="section-title">
                    Assigned Roles
                    <c-button size="sm" variant="secondary" @click=${() => this._openAddRoleModal()}>+ Add Role</c-button>
                  </div>
                  ${rolesLoading
              ? html`<div class="empty-state">Loading...</div>`
              : groupRoles.length > 0
                ? html`
                        <ul class="item-list">
                          ${groupRoles.map(role => html`
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

                <!-- Members Section -->
                <div class="section">
                  <div class="section-title">Members</div>
                  ${groupMembers.length > 0
              ? html`
                      <ul class="item-list">
                        ${groupMembers.map(member => html`
                          <li>
                            <span>
                              <span class="item-name">${member.email || member.username || member.id}</span>
                            </span>
                          </li>
                        `)}
                      </ul>
                    `
              : html`<div class="empty-state">No members in this group.</div>`}
                </div>
              `
          : html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Group not found.</div>`}
      </c-page-layout>

      <c-modal title="Add Role to Group" class="add-role-modal" @close=${() => this._closeAddRoleModal()}>
        ${showAddRoleModal ? html`
          <div class="form">
            <div class="field">
              <label class="field-label">Select Role</label>
              <select class="field-select" id="role-select">
                <option value="">-- Select a role --</option>
                ${availableRoles.map(r => html`<option value=${r.id}>${r.name}${r.description ? ` - ${r.description}` : ''}</option>`)}
              </select>
            </div>
          </div>
        ` : ''}
        <div slot="footer">
          <c-button variant="secondary" @click=${() => this._closeAddRoleModal()}>Cancel</c-button>
          <c-button variant="primary" ?disabled=${addRoleLoading} @click=${() => {
        const select = this.shadowRoot.getElementById('role-select');
        if (select && select.value) this._addRole(select.value);
      }}>
            ${addRoleLoading ? 'Adding...' : 'Add Role'}
          </c-button>
        </div>
      </c-modal>
    `;
  }
}

customElements.define('group-detail-page', GroupDetailPage);
