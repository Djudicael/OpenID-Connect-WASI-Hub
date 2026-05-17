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
      roleSearch: '',
      rolePage: 1,
      rolePageSize: 20,
      roleTotal: 0,
      selectedRoleId: '',
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
    super.disconnectedCallback();
    window.removeEventListener('beforeunload', this._onBeforeUnload);
    clearTimeout(this._roleSearchTimer);
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
      if (err.name === "AbortError") return;
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
      if (err.name === "AbortError") return;
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
      if (err.name === "AbortError") return;
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
      if (err.name === "AbortError") return;
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
    this.setState({
      showAddRoleModal: true,
      addRoleLoading: false,
      roleSearch: '',
      rolePage: 1,
      selectedRoleId: '',
    });
    requestAnimationFrame(() => {
      const modal = this.shadowRoot.querySelector('c-modal.add-role-modal');
      if (modal) modal.open();
    });
    this._loadAvailableRoles('', 1);
  }

  _closeAddRoleModal() {
    const modal = this.shadowRoot.querySelector('c-modal.add-role-modal');
    if (modal) modal.close();
    this.setState({ showAddRoleModal: false, selectedRoleId: '' });
  }

  async _loadAvailableRoles(search = this._state.roleSearch, page = this._state.rolePage) {
    const group = this._state.group;
    if (!group?.realm_id) {
      this.setState({ availableRoles: [], roleTotal: 0 });
      return;
    }

    try {
      const pageSize = this._state.rolePageSize;
      const offset = (page - 1) * pageSize;
      const data = await listRoles({
        realm_id: group.realm_id,
        ...(search ? { search } : {}),
        limit: String(pageSize),
        offset: String(offset),
      }, this.signal);
      const assignedIds = new Set((this._state.groupRoles || []).map(r => r.id));
      const available = (data.items || []).filter(r => !assignedIds.has(r.id));
      this.setState({ availableRoles: available, roleTotal: data.total || 0, rolePage: page });
    } catch (err) {
      if (err.name === "AbortError") return;
      this.setState({ availableRoles: [], roleTotal: 0 });
    }
  }

  _onRoleSearch(e) {
    const roleSearch = e.target.value;
    this.setState({ roleSearch, rolePage: 1, selectedRoleId: '' });
    clearTimeout(this._roleSearchTimer);
    this._roleSearchTimer = setTimeout(() => this._loadAvailableRoles(roleSearch, 1), 300);
  }

  async _onRolePageChange(e) {
    const nextPage = e.detail.page;
    await this.setState({ rolePage: nextPage, selectedRoleId: '' });
    this._loadAvailableRoles(this._state.roleSearch, nextPage);
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
      if (err.name === "AbortError") return;
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
      if (err.name === "AbortError") return;
      showToast('Failed to remove role', 'error');
    }
  }

  template() {
    const { group, loading, saving, dirty, groupRoles, groupMembers, rolesLoading, showAddRoleModal, availableRoles, roleSearch, rolePage, rolePageSize, roleTotal, selectedRoleId, addRoleLoading } = this._state;
    return html`
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
              <label class="field-label">Search Roles</label>
              <input class="field-input" type="text" placeholder="Search roles..." .value=${roleSearch} @input=${(e) => this._onRoleSearch(e)} />
            </div>
            <div class="field">
              <label class="field-label">Select Role</label>
              <select class="field-select" .value=${selectedRoleId} @change=${(e) => this.setState({ selectedRoleId: e.target.value })}>
                <option value="">-- Select a role --</option>
                ${availableRoles.map(r => html`<option value=${r.id}>${r.name}${r.description ? ` - ${r.description}` : ''}</option>`)}
              </select>
              <div class="hint">Search and page through roles in this group's realm.</div>
            </div>
            <c-pagination .page=${rolePage} .pageSize=${rolePageSize} .total=${roleTotal} @page-change=${(e) => this._onRolePageChange(e)}></c-pagination>
          </div>
        ` : ''}
        <div slot="footer">
          <c-button variant="secondary" @click=${() => this._closeAddRoleModal()}>Cancel</c-button>
          <c-button variant="primary" ?disabled=${addRoleLoading || !selectedRoleId} @click=${() => this._addRole(selectedRoleId)}>
            ${addRoleLoading ? 'Adding...' : 'Add Role'}
          </c-button>
        </div>
      </c-modal>
    `;
  }
}

customElements.define('group-detail-page', GroupDetailPage);
