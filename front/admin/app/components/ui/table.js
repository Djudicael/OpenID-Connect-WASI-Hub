import { html } from 'lit-html';
import { BaseComponent } from '../../core/component.js';

class Table extends BaseComponent {
  static get observedAttributes() {
    return ['columns'];
  }

  constructor() {
    super();
    this._state = { columns: [], rows: [], emptyText: 'No data available' };
  }

  attributeChangedCallback(name, oldVal, newVal) {
    if (name === 'columns' && newVal) {
      try {
        this.setState({ columns: JSON.parse(newVal) });
      } catch {
        this.setState({ columns: newVal.split(',').map(c => ({ key: c.trim(), label: c.trim() })) });
      }
    }
  }

  get rows() {
    return this._state.rows;
  }

  set rows(value) {
    this.setState({ rows: value });
  }

  get columns() {
    return this._state.columns;
  }

  set columns(value) {
    this.setState({ columns: value });
  }

  setData(rows) {
    this.setState({ rows });
  }

  template() {
    const { columns, rows, emptyText } = this._state;
    return html`
      <div class="table-wrap">
        ${rows.length === 0
        ? html`<div class="empty">${emptyText}</div>`
        : html`
              <table>
                <thead>
                  <tr>
                    ${columns.map(col => html`<th>${col.label || col.key}</th>`)}
                  </tr>
                </thead>
                <tbody>
                  ${rows.map(row => html`
                    <tr>
                      ${columns.map(col => html`<td>${this._renderCell(row, col)}</td>`)}
                    </tr>
                  `)}
                </tbody>
              </table>
            `}
      </div>
    `;
  }

  _renderCell(row, col) {
    if (col.render) {
      return col.render(row[col.key], row);
    }
    const val = row[col.key];
    if (val === null || val === undefined) return '-';
    if (typeof val === 'boolean') return val ? 'Yes' : 'No';
    return String(val);
  }
}

customElements.define('c-table', Table);
