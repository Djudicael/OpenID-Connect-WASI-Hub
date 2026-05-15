import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { getRole, updateRole } from '../services/role-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';

class RoleDetailPage extends BaseComponent {
  constructor() {
    super();
    this._state = { role: null, savedRole: null, loading: true, saving: false, dirty: false };
    this._onBeforeUnload = this._onBeforeUnload.bind(this);
  }

  connectedCallback() {
    super.connectedCallback();
    if (this.params && this.params.id) {
      this._loadRole(this.params.id);
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
    const { role, savedRole } = this._state;
    if (!role || !savedRole) return false;
    return (
      role.name !== savedRole.name ||
      role.description !== savedRole.description ||
      role.permissions !== savedRole.permissions
    );
  }

  async _loadRole(id) {
    this.setState({ loading: true });
    try {
      const role = await getRole(id);
      // Normalize permissions to a comma-separated string for editing
      const normalized = {
        ...role,
        permissions: Array.isArray(role.permissions) ? role.permissions.join(', ') : (role.permissions || ''),
      };
      this.setState({ role: normalized, savedRole: { ...normalized }, loading: false, dirty: false });
    } catch (err) {
      showToast('Failed to load role', 'error');
      this.setState({ loading: false });
    }
  }

  async _save() {
    const role = this._state.role;
    if (!role) return;
    this.setState({ saving: true });
    try {
      const permissions = typeof role.permissions === 'string'
        ? role.permissions.split(',').map(p => p.trim()).filter(Boolean)
        : role.permissions;
      await updateRole(role.id, {
        name: role.name,
        description: role.description,
        permissions,
      });
      showToast('Role updated', 'success');
      const savedRole = { ...role };
      this.setState({ saving: false, savedRole, dirty: false });
    } catch (err) {
      showToast('Failed to update role', 'error');
      this.setState({ saving: false });
    }
  }

  _updateField(field, value) {
    const role = { ...this._state.role, [field]: value };
    const savedRole = this._state.savedRole;
    const dirty = (
      role.name !== savedRole.name ||
      role.description !== savedRole.description ||
      role.permissions !== savedRole.permissions
    );
    this.setState({ role, dirty });
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

  template() {
    const { role, loading, saving, dirty } = this._state;
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
        .hint {
          font-size: 0.75rem;
          color: var(--color-text-muted);
          margin-top: 0.25rem;
        }
        .actions { display: flex; gap: 0.5rem; margin-top: 1.5rem; }
      </style>
      <c-page-layout title="Role Details">
        <span class="back-link" @click=${() => this._navigateAway('/roles')}>
          &larr; Back to Roles
        </span>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : role
          ? html`
                <div class="form">
                  <div class="field">
                    <label class="field-label">Name</label>
                    <input class="field-input" type="text" .value=${role.name || ''} @input=${(e) => this._updateField('name', e.target.value)} />
                  </div>
                  <div class="field">
                    <label class="field-label">Description</label>
                    <input class="field-input" type="text" .value=${role.description || ''} @input=${(e) => this._updateField('description', e.target.value)} />
                  </div>
                  <div class="field">
                    <label class="field-label">Permissions</label>
                    <input class="field-input" type="text" .value=${role.permissions || ''} @input=${(e) => this._updateField('permissions', e.target.value)} />
                    <div class="hint">Comma-separated list of permissions</div>
                  </div>
                  <div class="actions">
                    <c-button variant="primary" ?disabled=${saving || !dirty} @click=${() => this._save()}>
                      ${saving ? 'Saving...' : 'Save Changes'}${dirty ? html`<span class="dirty-indicator"></span>` : ''}
                    </c-button>
                    <c-button variant="ghost" @click=${() => this._navigateAway('/roles')}>Cancel</c-button>
                  </div>
                </div>
              `
          : html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Role not found.</div>`}
      </c-page-layout>
    `;
  }
}

customElements.define('role-detail-page', RoleDetailPage);
