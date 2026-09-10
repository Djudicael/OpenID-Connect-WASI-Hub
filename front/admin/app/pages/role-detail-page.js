import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { getRole, updateRole, listRoles, listRoleComposites, addRoleComposite, removeRoleComposite } from '../services/role-service.js';
import { listClients } from '../services/client-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';
import { handleApiError } from '../utils/error-handler.js';

class RoleDetailPage extends BaseComponent {
  constructor() {
    super();
    this._state = { role: null, savedRole: null, loading: true, saving: false, dirty: false, composites: [], availableRoles: [], clients: [], selectedCompositeId: '', compositeLoading: false };
    this._onBeforeUnload = this._onBeforeUnload.bind(this);
  }

  connectedCallback() {
    super.connectedCallback();
    if (this.params?.id) this._loadRole(this.params.id);
    window.addEventListener('beforeunload', this._onBeforeUnload);
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    window.removeEventListener('beforeunload', this._onBeforeUnload);
  }

  _onBeforeUnload(e) { if (this._state.dirty) { e.preventDefault(); e.returnValue = ''; } }

  async _loadRole(id) {
    this.setState({ loading: true });
    try {
      const role = await getRole(id, this.signal);
      const normalized = { ...role, permissions: Array.isArray(role.permissions) ? role.permissions.join(', ') : (role.permissions || '') };
      await this.setState({ role: normalized, savedRole: { ...normalized }, loading: false, dirty: false });
      await this._loadRelated();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to load role');
      this.setState({ loading: false });
    }
  }

  async _loadRelated() {
    const { role } = this._state;
    if (!role) return;
    try {
      const [compositeData, roleData, clientData] = await Promise.all([
        listRoleComposites(role.id, this.signal),
        listRoles({ realm_id: role.realm_id, limit: '1000', offset: '0' }, this.signal),
        listClients({ realm_id: role.realm_id, limit: '1000', offset: '0' }, this.signal),
      ]);
      this.setState({ composites: compositeData.items || [], availableRoles: roleData.items || [], clients: clientData.items || [] });
    } catch (err) {
      if (err.name !== 'AbortError') handleApiError(err, 'Failed to load composite roles');
    }
  }

  async _save() {
    const role = this._state.role;
    if (!role) return;
    this.setState({ saving: true });
    try {
      const permissions = role.permissions.split(',').map(value => value.trim()).filter(Boolean);
      await updateRole(role.id, { name: role.name, description: role.description, permissions });
      showToast('Role updated', 'success');
      this.setState({ saving: false, savedRole: { ...role }, dirty: false });
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to update role');
      this.setState({ saving: false });
    }
  }

  _updateField(field, value) {
    const role = { ...this._state.role, [field]: value };
    const saved = this._state.savedRole;
    this.setState({ role, dirty: role.name !== saved.name || role.description !== saved.description || role.permissions !== saved.permissions });
  }

  async _addComposite() {
    const { role, selectedCompositeId } = this._state;
    if (!role || !selectedCompositeId) return;
    this.setState({ compositeLoading: true });
    try {
      await addRoleComposite(role.id, selectedCompositeId, this.signal);
      showToast('Composite role added', 'success');
      await this.setState({ selectedCompositeId: '', compositeLoading: false });
      await this._loadRelated();
    } catch (err) {
      if (err.name === 'AbortError') return;
      handleApiError(err, 'Failed to add composite role');
      this.setState({ compositeLoading: false });
    }
  }

  async _removeComposite(childId) {
    try {
      await removeRoleComposite(this._state.role.id, childId, this.signal);
      showToast('Composite role removed', 'success');
      await this._loadRelated();
    } catch (err) { if (err.name !== 'AbortError') handleApiError(err, 'Failed to remove composite role'); }
  }

  _scopeLabel(role) {
    if (!role?.client_id) return 'Realm role';
    const client = this._state.clients.find(item => item.id === role.client_id);
    return `Client role: ${client?.client_id || client?.name || role.client_id}`;
  }

  _navigateAway(path) {
    if (this._state.dirty && !confirm('You have unsaved changes. Are you sure you want to leave?')) return;
    this.setState({ dirty: false });
    navigate(path);
  }

  template() {
    const { role, loading, saving, dirty, composites, availableRoles, selectedCompositeId, compositeLoading } = this._state;
    const assigned = new Set(composites.map(item => item.id));
    const choices = availableRoles.filter(item => item.id !== role?.id && !assigned.has(item.id));
    return html`<c-page-layout title="Role Details">
      <span class="back-link" @click=${() => this._navigateAway('/roles')}>&larr; Back to Roles</span>
      ${loading ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>` : role ? html`
        <div class="form">
          <div class="field"><label class="field-label">Role type</label><input class="field-input" .value=${this._scopeLabel(role)} disabled /></div>
          <div class="field"><label class="field-label">Name</label><input class="field-input" .value=${role.name || ''} @input=${e => this._updateField('name', e.target.value)} /></div>
          <div class="field"><label class="field-label">Description</label><input class="field-input" .value=${role.description || ''} @input=${e => this._updateField('description', e.target.value)} /></div>
          <div class="field"><label class="field-label">Permissions</label><input class="field-input" .value=${role.permissions || ''} @input=${e => this._updateField('permissions', e.target.value)} /><div class="hint">Comma-separated list of permissions</div></div>
          <div class="actions"><c-button variant="primary" ?disabled=${saving || !dirty} @click=${() => this._save()}>${saving ? 'Saving...' : 'Save Changes'}</c-button><c-button variant="ghost" @click=${() => this._navigateAway('/roles')}>Cancel</c-button></div>
        </div>
        <section style="margin-top:2rem">
          <h2>Composite roles</h2>
          <p class="hint">Anyone assigned this role also receives every role listed here, including roles inherited through nested composites.</p>
          <div style="display:flex;gap:0.75rem;align-items:end;margin:1rem 0">
            <div class="field" style="flex:1;margin:0"><label class="field-label" for="composite-role">Add included role</label><select class="field-select" id="composite-role" .value=${selectedCompositeId} @change=${e => this.setState({ selectedCompositeId: e.target.value })}><option value="">Select a role</option>${choices.map(item => html`<option value=${item.id}>${item.name} (${this._scopeLabel(item)})</option>`)}</select></div>
            <c-button variant="primary" ?disabled=${compositeLoading || !selectedCompositeId} @click=${() => this._addComposite()}>Add role</c-button>
          </div>
          ${composites.length ? html`<div style="display:grid;gap:0.5rem">${composites.map(item => html`<div style="display:flex;justify-content:space-between;align-items:center;padding:0.75rem;border:1px solid var(--color-border);border-radius:var(--radius-md)"><div><strong>${item.name}</strong><div class="hint">${this._scopeLabel(item)}</div></div><c-button size="sm" variant="danger" @click=${() => this._removeComposite(item.id)}>Remove</c-button></div>`)}</div>` : html`<div class="empty-state"><div class="empty-state-text">This role does not include other roles yet.</div></div>`}
        </section>` : html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Role not found.</div>`}
    </c-page-layout>`;
  }
}

customElements.define('role-detail-page', RoleDetailPage);
