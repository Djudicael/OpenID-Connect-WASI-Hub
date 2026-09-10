import { html } from 'lit-html';
import { BaseComponent } from '../core/component.js';
import { getRealm, updateRealm, previewEmailTemplate } from '../services/realm-service.js';
import { navigate } from '../core/router.js';
import { showToast } from '../components/ui/toast.js';

class RealmDetailPage extends BaseComponent {
  constructor() {
    super();
    this._state = { realm: null, savedRealm: null, loading: true, saving: false, dirty: false, presentationLocale: 'en', emailTemplate: 'password_reset', emailPreview: null };
    this._onBeforeUnload = this._onBeforeUnload.bind(this);
    this._previousTheme = null;
  }

  connectedCallback() {
    super.connectedCallback();
    if (this.params && this.params.id) {
      this._loadRealm(this.params.id);
    }
    window.addEventListener('beforeunload', this._onBeforeUnload);
  }

  disconnectedCallback() {
    window.removeEventListener('beforeunload', this._onBeforeUnload);
    this._restoreTheme();
    super.disconnectedCallback();
  }

  _onBeforeUnload(e) {
    if (this._state.dirty) {
      e.preventDefault();
      e.returnValue = '';
    }
  }

  _computeDirty(realm, savedRealm = this._state.savedRealm) {
    if (!realm || !savedRealm) return false;
    return (
      realm.name !== savedRealm.name ||
      realm.display_name !== savedRealm.display_name ||
      realm.enabled !== savedRealm.enabled ||
      JSON.stringify(realm.config?.theme || {}) !== JSON.stringify(savedRealm.config?.theme || {}) ||
      JSON.stringify(realm.config?.localization || {}) !== JSON.stringify(savedRealm.config?.localization || {}) ||
      JSON.stringify(realm.config?.email_templates || {}) !== JSON.stringify(savedRealm.config?.email_templates || {}) ||
      JSON.stringify(realm.config?.offline_sessions || {}) !== JSON.stringify(savedRealm.config?.offline_sessions || {}) ||
      JSON.stringify(realm.config?.authentication_flow || {}) !== JSON.stringify(savedRealm.config?.authentication_flow || {})
    );
  }

  get _isDirty() {
    return this._computeDirty(this._state.realm, this._state.savedRealm);
  }

  _getThemeValue(realm, key) {
    return realm?.config?.theme?.[key] || '';
  }

  async _loadRealm(id) {
    this.setState({ loading: true });
    try {
      const realm = await getRealm(id);
      // Ensure config/theme objects exist for binding
      if (!realm.config) realm.config = {};
      if (!realm.config.theme) realm.config.theme = {};
      if (realm.config.theme.bg_color && !realm.config.theme.background_color) realm.config.theme.background_color = realm.config.theme.bg_color;
      if (!realm.config.localization) realm.config.localization = { default_locale: 'en', supported_locales: ['en'], messages: {} };
      if (!realm.config.localization.messages) realm.config.localization.messages = {};
      if (!realm.config.email_templates) realm.config.email_templates = { locales: {} };
      if (!realm.config.email_templates.locales) realm.config.email_templates.locales = {};
      if (!realm.config.offline_sessions) realm.config.offline_sessions = {
        idle_seconds: 2592000,
        max_seconds: 7776000,
      };
      if (!realm.config.authentication_flow) realm.config.authentication_flow = {
        enabled: false,
        action_order: ['update_password', 'verify_email', 'update_profile', 'configure_mfa', 'accept_terms'],
        require_verified_email: false,
        require_complete_profile: false,
        require_mfa: false,
        terms: { enabled: false, version: '', text: '' },
        step_up: { enabled: false, client_ids: [], scopes: [], max_auth_age_seconds: null },
      };
      this._applyTheme(realm.config.theme);
      this.setState({ realm, savedRealm: JSON.parse(JSON.stringify(realm)), loading: false, dirty: false, presentationLocale: realm.config.localization.default_locale || 'en' });
    } catch (err) {
      if (err.name === "AbortError") return;
      showToast('Failed to load realm', 'error');
      this.setState({ loading: false });
    }
  }

  async _save() {
    const realm = this._state.realm;
    if (!realm) return;
    this.setState({ saving: true });
    try {
      await updateRealm(realm.id, {
        name: realm.name,
        display_name: realm.display_name,
        enabled: realm.enabled,
        config: realm.config,
      });
      showToast('Realm updated', 'success');
      this.setState({ saving: false, savedRealm: JSON.parse(JSON.stringify(realm)), dirty: false });
    } catch (err) {
      if (err.name === "AbortError") return;
      showToast('Failed to update realm', 'error');
      this.setState({ saving: false });
    }
  }

  _updateField(field, value) {
    const realm = { ...this._state.realm, [field]: value };
    const dirty = this._computeDirty(realm);
    this.setState({ realm, dirty });
  }

  _updateThemeField(key, value) {
    const realm = { ...this._state.realm };
    realm.config = { ...realm.config };
    realm.config.theme = { ...realm.config.theme, [key]: value };
    this._applyTheme(realm.config.theme);
    const dirty = this._computeDirty(realm);
    this.setState({ realm, dirty });
  }

  _applyTheme(theme = {}) {
    const root = document.documentElement;
    const values = {
      '--color-primary': theme.primary_color,
      '--color-bg': theme.background_color || theme.bg_color,
      '--color-surface': theme.card_color,
      '--color-text': theme.text_color,
      '--font-sans': theme.font_family,
    };
    if (!this._previousTheme) {
      this._previousTheme = Object.fromEntries(
        Object.keys(values).map(name => [name, root.style.getPropertyValue(name)])
      );
    }
    Object.entries(values).forEach(([name, value]) => {
      if (value) root.style.setProperty(name, value);
      else root.style.removeProperty(name);
    });
  }

  _restoreTheme() {
    if (!this._previousTheme) return;
    const root = document.documentElement;
    Object.entries(this._previousTheme).forEach(([name, value]) => {
      if (value) root.style.setProperty(name, value);
      else root.style.removeProperty(name);
    });
    this._previousTheme = null;
  }

  _updateLocalization(key, value) {
    const realm = structuredClone(this._state.realm);
    realm.config.localization[key] = value;
    if (key === 'supported_locales' && !value.includes(realm.config.localization.default_locale)) {
      realm.config.localization.default_locale = value[0] || 'en';
    }
    const presentationLocale = key === 'supported_locales' && !value.includes(this._state.presentationLocale) ? (value[0] || 'en') : this._state.presentationLocale;
    this.setState({ realm, presentationLocale, emailPreview: null, dirty: this._computeDirty(realm) });
  }

  _updateMessage(key, value) {
    const realm = structuredClone(this._state.realm);
    const locale = this._state.presentationLocale;
    realm.config.localization.messages[locale] = { ...(realm.config.localization.messages[locale] || {}), [key]: value };
    this.setState({ realm, dirty: this._computeDirty(realm) });
  }

  _updateEmailTemplate(field, value) {
    const realm = structuredClone(this._state.realm);
    const { presentationLocale: locale, emailTemplate: name } = this._state;
    const locales = realm.config.email_templates.locales;
    locales[locale] = { ...(locales[locale] || {}) };
    locales[locale][name] = { subject: '', text: '', html: '', ...(locales[locale][name] || {}), [field]: value };
    this.setState({ realm, emailPreview: null, dirty: this._computeDirty(realm) });
  }

  async _previewEmail() {
    if (this._isDirty) {
      showToast('Save changes before previewing the email', 'error');
      return;
    }
    try {
      const emailPreview = await previewEmailTemplate(this._state.realm.id, this._state.emailTemplate, this._state.presentationLocale);
      this.setState({ emailPreview });
    } catch (err) {
      if (err.name !== 'AbortError') showToast(err.message || 'Unable to preview email', 'error');
    }
  }

  _messageValue(key) {
    return this._state.realm.config.localization.messages?.[this._state.presentationLocale]?.[key] || '';
  }

  _templateValue(field) {
    return this._state.realm.config.email_templates.locales?.[this._state.presentationLocale]?.[this._state.emailTemplate]?.[field] || '';
  }

  _updateFlowField(key, value) {
    const realm = structuredClone(this._state.realm);
    realm.config.authentication_flow[key] = value;
    this.setState({ realm, dirty: this._computeDirty(realm) });
  }

  _updateOfflineDays(key, value) {
    const realm = structuredClone(this._state.realm);
    const days = Math.max(1, Number(value) || 1);
    realm.config.offline_sessions[key] = Math.round(days * 86400);
    this.setState({ realm, dirty: this._computeDirty(realm) });
  }

  _updateNestedFlow(section, key, value) {
    const realm = structuredClone(this._state.realm);
    realm.config.authentication_flow[section] = { ...realm.config.authentication_flow[section], [key]: value };
    this.setState({ realm, dirty: this._computeDirty(realm) });
  }

  _moveAction(index, offset) {
    const order = [...this._state.realm.config.authentication_flow.action_order];
    const next = index + offset;
    if (next < 0 || next >= order.length) return;
    [order[index], order[next]] = [order[next], order[index]];
    this._updateFlowField('action_order', order);
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
    const { realm, loading, saving, dirty } = this._state;
    return html`
      <c-page-layout title="Realm Details">
        <span class="back-link" @click=${() => this._navigateAway('/realms')}>
          &larr; Back to Realms
        </span>
        ${loading
        ? html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Loading...</div>`
        : realm
          ? html`
                <div class="realm-id">ID: ${realm.id}</div>
                <div class="form">
                  <div class="field">
                    <label class="field-label">Name</label>
                    <input class="field-input" type="text" .value=${realm.name || ''} @input=${(e) => this._updateField('name', e.target.value)} />
                    <div class="hint">Machine-readable identifier</div>
                  </div>
                  <div class="field">
                    <label class="field-label">Display Name</label>
                    <input class="field-input" type="text" .value=${realm.display_name || ''} @input=${(e) => this._updateField('display_name', e.target.value)} />
                    <div class="hint">Human-readable name</div>
                  </div>
                  <label class="checkbox-row">
                    <input type="checkbox" ?checked=${realm.enabled} @change=${(e) => this._updateField('enabled', e.target.checked)} />
                    Enabled
                  </label>
                  <hr style="border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0;" />
                  <div data-doc-section="theme">
                  <h3 style="font-size:1rem;font-weight:600;margin:0 0 1rem 0;">Theme</h3>
                  <div class="field">
                    <label class="field-label">Login Title</label>
                    <input class="field-input" type="text" .value=${this._getThemeValue(realm, 'login_title')} @input=${(e) => this._updateThemeField('login_title', e.target.value)} />
                    <div class="hint">Shown on the realm login page (defaults to display name)</div>
                  </div>
                  <div class="field">
                    <label class="field-label">Logo URL</label>
                    <input class="field-input" type="text" .value=${this._getThemeValue(realm, 'logo_url')} @input=${(e) => this._updateThemeField('logo_url', e.target.value)} />
                    <div class="hint">Optional logo image URL for the login page</div>
                  </div>
                  <div class="field">
                    <label class="field-label">Primary Color</label>
                    <input class="field-input" type="color" .value=${this._getThemeValue(realm, 'primary_color') || '#2563eb'} @input=${(e) => this._updateThemeField('primary_color', e.target.value)} />
                    <div class="hint">Button and accent color</div>
                  </div>
                  <div class="field">
                    <label class="field-label">Background Color</label>
                    <input class="field-input" type="color" .value=${this._getThemeValue(realm, 'background_color') || '#f8fafc'} @input=${(e) => this._updateThemeField('background_color', e.target.value)} />
                    <div class="hint">Login page background color</div>
                  </div>
                  <div class="field-row">
                    <div class="field"><label class="field-label">Card Color</label><input class="field-input" type="color" .value=${this._getThemeValue(realm, 'card_color') || '#ffffff'} @input=${e=>this._updateThemeField('card_color',e.target.value)} /></div>
                    <div class="field"><label class="field-label">Text Color</label><input class="field-input" type="color" .value=${this._getThemeValue(realm, 'text_color') || '#111827'} @input=${e=>this._updateThemeField('text_color',e.target.value)} /></div>
                  </div>
                  <div class="field"><label class="field-label">Favicon URL</label><input class="field-input" type="text" .value=${this._getThemeValue(realm,'favicon_url')} @input=${e=>this._updateThemeField('favicon_url',e.target.value)} /><div class="hint">Use an HTTPS URL or a path beginning with /</div></div>
                  <div class="field"><label class="field-label">Font Family</label><input class="field-input" type="text" .value=${this._getThemeValue(realm,'font_family') || 'system-ui, sans-serif'} @input=${e=>this._updateThemeField('font_family',e.target.value)} /></div>
                  <div class="field"><label class="field-label">Footer Text</label><input class="field-input" type="text" .value=${this._getThemeValue(realm,'footer_text') || 'Powered by OpenID Connect Hub'} @input=${e=>this._updateThemeField('footer_text',e.target.value)} /></div>
                  <a class="btn btn--ghost btn--md" href=${`/realms/${encodeURIComponent(realm.name)}/login?ui_locales=${encodeURIComponent(this._state.presentationLocale)}`} target="_blank">Preview sign-in page</a>
                  </div>
                  <hr style="border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0;" />
                  <div data-doc-section="localization">
                    <h3 style="font-size:1rem;font-weight:600;margin:0 0 1rem 0;">Localization</h3>
                    <div class="field"><label class="field-label">Supported Locales</label><input class="field-input" .value=${realm.config.localization.supported_locales.join(', ')} @change=${e=>this._updateLocalization('supported_locales',e.target.value.split(',').map(v=>v.trim()).filter(Boolean))} /><div class="hint">Comma-separated language tags, such as en, fr, or fr-CA.</div></div>
                    <div class="field-row">
                      <div class="field"><label class="field-label">Default Locale</label><select class="field-select" .value=${realm.config.localization.default_locale} @change=${e=>this._updateLocalization('default_locale',e.target.value)}>${realm.config.localization.supported_locales.map(locale=>html`<option value=${locale}>${locale}</option>`)}</select></div>
                      <div class="field"><label class="field-label">Edit Translations For</label><select class="field-select" .value=${this._state.presentationLocale} @change=${e=>this.setState({presentationLocale:e.target.value})}>${realm.config.localization.supported_locales.map(locale=>html`<option value=${locale}>${locale}</option>`)}</select></div>
                    </div>
                    ${[['page_title','Browser title'],['subtitle','Sign-in message'],['email','Email label'],['email_placeholder','Email placeholder'],['password','Password label'],['sign_in','Sign-in button'],['signing_in','Signing-in progress'],['login_failed','Sign-in error'],['toggle_password','Password visibility label']].map(([key,label])=>html`<div class="field"><label class="field-label">${label}</label><input class="field-input" .value=${this._messageValue(key)} @input=${e=>this._updateMessage(key,e.target.value)} placeholder="Use built-in text" /></div>`)}
                  </div>
                  <hr style="border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0;" />
                  <div data-doc-section="email-templates">
                    <h3 style="font-size:1rem;font-weight:600;margin:0 0 1rem 0;">Email Templates</h3>
                    <p class="hint">Customize messages for each locale. Empty fields use the built-in template.</p>
                    <div class="field"><label class="field-label">Template</label><select class="field-select" .value=${this._state.emailTemplate} @change=${e=>this.setState({emailTemplate:e.target.value,emailPreview:null})}><option value="password_reset">Password reset</option><option value="email_verification">Email verification</option><option value="organization_invitation">Organization invitation</option></select></div>
                    <div class="field"><label class="field-label">Subject</label><input class="field-input" .value=${this._templateValue('subject')} @input=${e=>this._updateEmailTemplate('subject',e.target.value)} /></div>
                    <div class="field"><label class="field-label">Plain-text Message</label><textarea class="field-textarea email-template-editor" .value=${this._templateValue('text')} @input=${e=>this._updateEmailTemplate('text',e.target.value)}></textarea></div>
                    <div class="field"><label class="field-label">HTML Message</label><textarea class="field-textarea email-template-editor" .value=${this._templateValue('html')} @input=${e=>this._updateEmailTemplate('html',e.target.value)}></textarea></div>
                    <div class="hint">Available placeholders: {{realm_name}}, {{action_url}}, {{expires_in}}, and {{user_name}}. Organization invitations use {{organization_name}} instead of {{user_name}}.</div>
                    <div class="actions"><c-button variant="ghost" @click=${()=>this._previewEmail()}>Preview saved template</c-button></div>
                    ${this._state.emailPreview ? html`<article class="email-preview"><strong>${this._state.emailPreview.subject}</strong><pre>${this._state.emailPreview.text}</pre>${this._state.emailPreview.html ? html`<iframe title="Email HTML preview" sandbox="" .srcdoc=${this._state.emailPreview.html}></iframe>` : ''}</article>` : ''}
                  </div>
                  <hr style="border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0;" />
                  <div data-doc-section="offline-sessions">
                    <h3 style="font-size:1rem;font-weight:600;margin:0 0 1rem 0;">Offline access</h3>
                    <p class="hint">Set how long approved applications can refresh access while a user is signed out.</p>
                    <div class="field">
                      <label class="field-label">Idle timeout (days)</label>
                      <input class="field-input" type="number" min="1" step="1" .value=${realm.config.offline_sessions.idle_seconds / 86400} @input=${e => this._updateOfflineDays('idle_seconds', e.target.value)} />
                      <div class="hint">The grant expires when the application does not use it for this long.</div>
                    </div>
                    <div class="field">
                      <label class="field-label">Maximum lifetime (days)</label>
                      <input class="field-input" type="number" min="1" step="1" .value=${realm.config.offline_sessions.max_seconds / 86400} @input=${e => this._updateOfflineDays('max_seconds', e.target.value)} />
                      <div class="hint">The grant expires after this time even when it is used regularly.</div>
                    </div>
                  </div>
                  <hr style="border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0;" />
                  <div data-doc-section="authentication-flow">
                  <h3 style="font-size:1rem;font-weight:600;margin:0 0 1rem 0;">Authentication flow</h3>
                  <label class="checkbox-row"><input type="checkbox" ?checked=${realm.config.authentication_flow.enabled} @change=${e=>this._updateFlowField('enabled',e.target.checked)} /> Enable realm authentication flow</label>
                  <p class="hint">Complete enabled checks before an application receives tokens.</p>
                  <div class="checkbox-grid">
                    <label class="checkbox-row"><input type="checkbox" ?checked=${realm.config.authentication_flow.require_verified_email} @change=${e=>this._updateFlowField('require_verified_email',e.target.checked)} /> Require a verified email address</label>
                    <label class="checkbox-row"><input type="checkbox" ?checked=${realm.config.authentication_flow.require_complete_profile} @change=${e=>this._updateFlowField('require_complete_profile',e.target.checked)} /> Require first and last name</label>
                    <label class="checkbox-row"><input type="checkbox" ?checked=${realm.config.authentication_flow.require_mfa} @change=${e=>this._updateFlowField('require_mfa',e.target.checked)} /> Require MFA enrollment</label>
                  </div>
                  <div class="section">
                    <div class="section-title">Action order</div>
                    <ul class="item-list">${realm.config.authentication_flow.action_order.map((action,index)=>html`<li><span class="item-name">${action.replaceAll('_',' ')}</span><span><button class="btn-icon" @click=${()=>this._moveAction(index,-1)} ?disabled=${index===0} aria-label="Move up">↑</button><button class="btn-icon" @click=${()=>this._moveAction(index,1)} ?disabled=${index===realm.config.authentication_flow.action_order.length-1} aria-label="Move down">↓</button></span></li>`)}</ul>
                  </div>
                  <div class="section">
                    <div class="section-title">Terms acceptance</div>
                    <label class="checkbox-row"><input type="checkbox" ?checked=${realm.config.authentication_flow.terms.enabled} @change=${e=>this._updateNestedFlow('terms','enabled',e.target.checked)} /> Require acceptance</label>
                    <div class="field"><label class="field-label">Terms version</label><input class="field-input" .value=${realm.config.authentication_flow.terms.version||''} @input=${e=>this._updateNestedFlow('terms','version',e.target.value)} placeholder="2026-09" /></div>
                    <div class="field"><label class="field-label">Terms shown to users</label><textarea class="field-textarea" .value=${realm.config.authentication_flow.terms.text||''} @input=${e=>this._updateNestedFlow('terms','text',e.target.value)}></textarea><div class="hint">Changing the version asks users to accept the new terms.</div></div>
                  </div>
                  <div class="section">
                    <div class="section-title">Step-up authentication</div>
                    <label class="checkbox-row"><input type="checkbox" ?checked=${realm.config.authentication_flow.step_up.enabled} @change=${e=>this._updateNestedFlow('step_up','enabled',e.target.checked)} /> Require MFA for matching requests</label>
                    <div class="field"><label class="field-label">Client IDs</label><input class="field-input" .value=${(realm.config.authentication_flow.step_up.client_ids||[]).join(', ')} @input=${e=>this._updateNestedFlow('step_up','client_ids',e.target.value.split(',').map(v=>v.trim()).filter(Boolean))} /><div class="hint">Comma-separated. Leave empty to match any client.</div></div>
                    <div class="field"><label class="field-label">Scopes</label><input class="field-input" .value=${(realm.config.authentication_flow.step_up.scopes||[]).join(', ')} @input=${e=>this._updateNestedFlow('step_up','scopes',e.target.value.split(',').map(v=>v.trim()).filter(Boolean))} /><div class="hint">A matching requested scope triggers step-up.</div></div>
                    <div class="field"><label class="field-label">Maximum authentication age (seconds)</label><input class="field-input" type="number" min="0" .value=${realm.config.authentication_flow.step_up.max_auth_age_seconds??''} @input=${e=>this._updateNestedFlow('step_up','max_auth_age_seconds',e.target.value===''?null:Number(e.target.value))} /></div>
                  </div>
                  </div>
                  <div class="actions">
                    <c-button variant="primary" ?disabled=${saving || !dirty} @click=${() => this._save()}>
                      ${saving ? 'Saving...' : 'Save Changes'}${dirty ? html`<span class="dirty-indicator"></span>` : ''}
                    </c-button>
                    <c-button variant="ghost" @click=${() => this._navigateAway('/realms')}>Cancel</c-button>
                  </div>
                </div>
              `
          : html`<div style="padding:2rem;text-align:center;color:var(--color-text-muted)">Realm not found.</div>`}
      </c-page-layout>
    `;
  }
}

customElements.define('realm-detail-page', RealmDetailPage);
