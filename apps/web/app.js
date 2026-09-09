import { ApiClient, apiErrorMessage, pathId, queryString, splitIds } from "./api.js";

export const VIEWS = Object.freeze({
  privacy: "材料脱敏",
  legal: "法律检索",
  templates: "文书模板",
  chat: "AI 对话",
  settings: "设置"
});

export const ENTITY_KINDS = Object.freeze([
  "person_name", "organization_name", "address", "phone_number", "email_address",
  "identity_number", "passport_number", "case_number", "bank_account", "landline_number",
  "organization_code", "business_license_number", "vehicle_plate", "ip_address", "social_account",
  "payment_account", "account_name", "contract_number", "tracking_number", "property_certificate_number", "custom"
]);

export function optionalAlias(value) {
  const alias = String(value || "").trim();
  return alias || null;
}

export const STATUS_LABELS = Object.freeze({
  queued: "排队中",
  extracting: "提取中",
  analyzing: "识别中",
  processing: "处理中",
  awaiting_consent: "等待云辅助授权",
  needs_review: "待复核",
  ready: "可用",
  partial: "部分完成",
  completed: "已完成",
  failed: "失败",
  cancelled: "已取消",
  revoked: "已撤销",
  expired: "已过期",
  running: "运行中",
  pending: "等待处理"
});

export function statusLabel(status) {
  const key = String(status || "").toLowerCase();
  return STATUS_LABELS[key] || (key ? key : "未知状态");
}

export function materialStatusTone(status) {
  const key = String(status || "").toLowerCase();
  if (["ready", "completed"].includes(key)) return "success";
  if (["failed", "revoked", "expired"].includes(key)) return "danger";
  if (["needs_review", "awaiting_consent", "partial"].includes(key)) return "warning";
  return "info";
}

export function field(object, keys, fallback = "") {
  if (!object || typeof object !== "object") return fallback;
  for (const key of keys) {
    const value = object[key];
    if (value !== undefined && value !== null && String(value) !== "") return value;
  }
  return fallback;
}

export function textValue(value, fallback = "") {
  if (value === undefined || value === null) return fallback;
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function node(tag, options = {}, children = []) {
  const element = document.createElement(tag);
  if (options.className) element.className = options.className;
  if (options.id) element.id = options.id;
  if (options.text !== undefined) element.textContent = options.text;
  if (options.type) element.type = options.type;
  if (options.value !== undefined) element.value = options.value;
  if (options.name) element.name = options.name;
  if (options.placeholder) element.placeholder = options.placeholder;
  if (options.checked !== undefined) element.checked = Boolean(options.checked);
  if (options.disabled !== undefined) element.disabled = Boolean(options.disabled);
  if (options.required !== undefined) element.required = Boolean(options.required);
  if (options.multiple !== undefined) element.multiple = Boolean(options.multiple);
  if (options.rows !== undefined) element.rows = options.rows;
  if (options.cols !== undefined) element.cols = options.cols;
  if (options.accept) element.accept = options.accept;
  if (options.autocomplete) element.autocomplete = options.autocomplete;
  if (options.href) element.href = options.href;
  if (options.download) element.download = options.download;
  if (options.role) element.setAttribute("role", options.role);
  if (options.ariaLabel) element.setAttribute("aria-label", options.ariaLabel);
  if (options.ariaLive) element.setAttribute("aria-live", options.ariaLive);
  if (options.title) element.title = options.title;
  if (options.events) {
    for (const [eventName, listener] of Object.entries(options.events)) element.addEventListener(eventName, listener);
  }
  for (const child of children) {
    if (child !== null && child !== undefined) element.append(child);
  }
  return element;
}

function button(label, onClick, className = "button") {
  return node("button", { className, type: "button", text: label, events: { click: onClick } });
}

function formButton(label, className = "button primary") {
  return node("button", { className, type: "submit", text: label });
}

function heading(level, text) {
  return node(`h${level}`, { text });
}

function labelFor(text, control) {
  const label = node("label", { className: "field-label", text });
  label.append(control);
  return label;
}

function fieldInput(label, options = {}) {
  const input = node("input", options);
  return labelFor(label, input);
}

function fieldSelect(label, options = {}) {
  const select = node("select", options);
  return labelFor(label, select);
}

function fieldTextArea(label, options = {}) {
  const textarea = node("textarea", options);
  return labelFor(label, textarea);
}

function panel(title, children = [], className = "panel") {
  const section = node("section", { className }, [heading(2, title)]);
  section.append(...children);
  return section;
}

function statusBox(text = "", tone = "") {
  return node("p", { className: `status-message${tone ? ` ${tone}` : ""}`, text, ariaLive: "polite" });
}

function setStatus(target, message, tone = "") {
  if (!target) return;
  target.className = `status-message${tone ? ` ${tone}` : ""}`;
  target.textContent = message;
}

function replaceChildren(target, children = []) {
  target.replaceChildren(...children.filter((child) => child !== null && child !== undefined));
}

function emptyState(message) {
  return node("p", { className: "empty-state", text: message });
}

function appendOption(select, value, label, selected = false) {
  const option = node("option", { value, text: label });
  option.selected = selected;
  select.append(option);
}

function safeFilename(name, extension) {
  const cleaned = String(name || "律师助手导出").replace(/[\\/:*?"<>|\u0000-\u001f]/gu, "_").slice(0, 100) || "律师助手导出";
  return extension && !cleaned.toLowerCase().endsWith(`.${extension}`) ? `${cleaned}.${extension}` : cleaned;
}

async function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  try {
    const anchor = node("a", { href: url, download: filename });
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

async function copyText(text) {
  if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") throw new Error("clipboard_unavailable");
  await navigator.clipboard.writeText(String(text || ""));
}

function getFragmentToken() {
  const hash = String(globalThis.location?.hash || "");
  if (!hash.startsWith("#")) return "";
  const params = new URLSearchParams(hash.slice(1));
  return params.get("token") || "";
}

function clearFragment() {
  if (!globalThis.history || !globalThis.location) return;
  globalThis.history.replaceState(null, "", `${globalThis.location.pathname}${globalThis.location.search}`);
}

function parseJsonList(value) {
  return Array.isArray(value) ? value : [];
}

function responseList(response, keys) {
  if (Array.isArray(response)) return response;
  for (const key of keys) {
    if (Array.isArray(response?.[key])) return response[key];
  }
  return [];
}

function formatDate(value) {
  const text = textValue(value);
  if (!text) return "";
  const date = new Date(text);
  return Number.isNaN(date.valueOf()) ? text : date.toLocaleString("zh-CN", { hour12: false });
}

function materialName(material) {
  return textValue(field(material, ["name", "filename", "file_name"]), "未命名材料");
}

function articleId(article) {
  return textValue(field(article, ["id", "articleId", "article_id"]));
}

export function legalArticleDocumentId(article) {
  return textValue(field(article, ["documentId", "document_id"]));
}

export function legalArticleDisplayTitle(article) {
  const documentTitle = textValue(field(article, ["documentTitle", "document_title"]));
  const number = textValue(field(article, ["articleNumber", "article_number"]));
  const articleTitle = textValue(field(article, ["articleTitle", "article_title", "title", "name"]));
  return [documentTitle, number, articleTitle].filter(Boolean).join(" · ") || "未命名条文";
}

export function legalRelationTarget(relation, currentDocumentId) {
  const fromId = textValue(field(relation, ["fromDocumentId", "from_document_id"]));
  const toId = textValue(field(relation, ["toDocumentId", "to_document_id"]));
  if (fromId && fromId === currentDocumentId) {
    const title = textValue(field(relation, ["toTitle", "to_title"]));
    return { documentId: toId, title: title || "关联法规" };
  }
  if (toId && toId === currentDocumentId) {
    const title = textValue(field(relation, ["fromTitle", "from_title"]));
    return { documentId: fromId, title: title || "关联法规" };
  }
  const title = textValue(field(relation, ["toTitle", "to_title", "fromTitle", "from_title"]));
  return { documentId: toId || fromId, title: title || "关联法规" };
}

function templateId(template) {
  return textValue(field(template, ["id", "templateId", "template_id"]));
}

function templateTitle(template) {
  return textValue(field(template, ["title", "name", "label"]), "未命名模板");
}

function resultId(material) {
  return textValue(field(material, ["result_id", "resultId"]));
}

function groupId(group) {
  return textValue(field(group, ["id", "groupId", "group_id"]));
}

export function mcpClientDetails(client, groups = []) {
  const clientGroupId = textValue(field(client, ["group_id", "groupId"]));
  const group = Array.isArray(groups) ? groups.find((item) => groupId(item) === clientGroupId) : null;
  const resolvedGroupName = textValue(field(group, ["name"]));
  return Object.freeze({
    groupId: clientGroupId,
    groupName: resolvedGroupName || (clientGroupId ? "未找到分组" : "未绑定分组"),
    inbox: textValue(field(client, ["inbox"]))
  });
}

export class WebApp {
  constructor(root, api = new ApiClient()) {
    this.root = root;
    this.api = api;
    this.state = {
      authenticated: false,
      csrfToken: "",
      view: "privacy",
      health: null,
      groups: [],
      selectedGroupId: "",
      materials: [],
      selectedMaterial: null,
      legalResults: [],
      legalBookmarks: [],
      selectedArticle: null,
      templates: [],
      providers: [],
      conversations: [],
      selectedConversation: null,
      mcpClients: [],
      taskTimer: null,
      chatAbort: null,
      pendingMcpToken: null
    };
    this.api.onUnauthenticated = () => this.requireLogin();
  }

  async start() {
    this.render();
    const token = getFragmentToken();
    if (token) {
      try {
        const session = await this.api.request("/session", { method: "POST", body: { token } });
        clearFragment();
        this.setSession(session);
      } catch (error) {
        clearFragment();
        this.state.authenticated = false;
        this.renderLogin(apiErrorMessage(error));
        return;
      }
    } else {
      try {
        const session = await this.api.request("/session");
        this.setSession(session);
      } catch {
        this.state.authenticated = false;
        this.renderLogin();
        return;
      }
    }
    await this.loadHealth();
    this.render();
  }

  setSession(session) {
    this.state.authenticated = Boolean(session && session.authenticated);
    this.state.csrfToken = textValue(session && session.csrf_token);
    this.api.setCsrfToken(this.state.csrfToken);
  }

  requireLogin() {
    this.state.authenticated = false;
    this.state.csrfToken = "";
    this.api.setCsrfToken("");
    this.renderLogin("会话已失效，请使用新的本地访问链接。", true);
  }

  async loadHealth() {
    try {
      this.state.health = await this.api.request("/health");
    } catch {
      this.state.health = null;
    }
  }

  navigate(view) {
    if (!Object.prototype.hasOwnProperty.call(VIEWS, view)) return;
    this.state.view = view;
    this.render();
  }

  render() {
    if (!this.state.authenticated) {
      this.renderLogin();
      return;
    }
    const shell = node("div", { className: "app-shell" });
    const header = node("header", { className: "app-header" });
    const brand = node("div", { className: "brand" }, [
      node("span", { className: "brand-mark", text: "律" }),
      node("div", {}, [node("strong", { text: "律师助手" }), node("span", { text: "本机脱敏与法律检索" })])
    ]);
    const nav = node("nav", { className: "main-nav", role: "navigation", ariaLabel: "主导航" });
    for (const [key, label] of Object.entries(VIEWS)) {
      const navButton = button(label, () => this.navigate(key), `nav-button${this.state.view === key ? " active" : ""}`);
      navButton.setAttribute("aria-current", this.state.view === key ? "page" : "false");
      nav.append(navButton);
    }
    const healthReady = ["ok", "ready"].includes(textValue(this.state.health?.status).toLowerCase());
    const health = node("span", { className: `health-dot${healthReady ? " online" : ""}`, text: healthReady ? "服务正常" : "服务检查中" });
    const healthButton = button("检查服务", async () => {
      health.textContent = "检查中";
      await this.loadHealth();
      const refreshedHealthReady = ["ok", "ready"].includes(textValue(this.state.health?.status).toLowerCase());
      health.className = `health-dot${refreshedHealthReady ? " online" : ""}`;
      health.textContent = refreshedHealthReady ? "服务正常" : "服务不可用";
    }, "button subtle");
    const headerActions = node("div", { className: "header-actions" }, [health, healthButton]);
    header.append(brand, nav, headerActions);
    const main = node("main", { className: "app-main" });
    shell.append(header, main);
    this.root.replaceChildren(shell);
    if (this.state.view === "privacy") this.renderPrivacy(main);
    else if (this.state.view === "legal") this.renderLegal(main);
    else if (this.state.view === "templates") this.renderTemplates(main);
    else if (this.state.view === "chat") this.renderChat(main);
    else this.renderSettings(main);
  }

  renderLogin(message = "", sessionExpired = false) {
    const wrapper = node("div", { className: "login-page" });
    const card = node("section", { className: "login-card" }, [
      node("span", { className: "brand-mark large", text: "律" }),
      heading(1, "律师助手"),
      node("p", { className: "muted", text: "本机 Web 工作台 · 材料先脱敏，再进入 AI" })
    ]);
    const form = node("form", { className: "stack-form" });
    const tokenInput = node("input", { type: "password", placeholder: "粘贴本地访问令牌", autocomplete: "off", required: true });
    form.append(labelFor("本地访问令牌", tokenInput));
    const status = statusBox(message, message ? "warning" : "");
    const submit = formButton("进入工作台", "button primary full");
    form.append(submit, status);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      submit.disabled = true;
      setStatus(status, "正在建立本机会话…");
      try {
        const session = await this.api.request("/session", { method: "POST", body: { token: tokenInput.value } });
        clearFragment();
        this.setSession(session);
        await this.loadHealth();
        this.render();
      } catch (error) {
        setStatus(status, apiErrorMessage(error), "danger");
        submit.disabled = false;
      }
    });
    card.append(form);
    if (sessionExpired) card.append(node("p", { className: "muted small", text: "浏览器会话只保留在本机 HttpOnly Cookie 中。" }));
    wrapper.append(card);
    this.root.replaceChildren(wrapper);
  }

  async renderPrivacy(main) {
    const title = node("div", { className: "page-title" }, [heading(1, "材料脱敏"), node("p", { text: "导入 TXT 或 DOCX，自动识别隐私信息，完成检查后再导出。" })]);
    const layout = node("div", { className: "workspace-grid privacy-grid" });
    const left = node("div", { className: "workspace-column" });
    const right = node("div", { className: "workspace-column" });
    layout.append(left, right);
    main.append(title, layout);
    const groupPanel = panel("材料分组");
    const groupRow = node("div", { className: "inline-form" });
    const groupSelect = node("select", { ariaLabel: "选择材料分组" });
    groupRow.append(groupSelect);
    const refreshGroups = button("刷新", () => this.loadPrivacyData(groupSelect, materialsList, detail, dictionaryList, dictionaryStatus), "button subtle");
    groupRow.append(refreshGroups);
    groupPanel.append(groupRow);
    const newGroupForm = node("form", { className: "inline-form" });
    const newGroupName = node("input", { type: "text", placeholder: "新分组名称", required: true });
    const addGroupButton = formButton("新建分组", "button secondary");
    const groupStatus = statusBox();
    newGroupForm.append(newGroupName, addGroupButton);
    newGroupForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      addGroupButton.disabled = true;
      try {
        await this.api.request("/groups", { method: "POST", body: { name: newGroupName.value.trim() } });
        newGroupName.value = "";
        setStatus(groupStatus, "分组已创建", "success");
        await this.loadPrivacyData(groupSelect, materialsList, detail, dictionaryList, dictionaryStatus);
      } catch (error) {
        setStatus(groupStatus, apiErrorMessage(error), "danger");
      } finally {
        addGroupButton.disabled = false;
      }
    });
    groupPanel.append(newGroupForm, groupStatus);
    const dictionaryPanel = panel("分组词典");
    const dictionaryList = node("div", { className: "dictionary-list" }, [emptyState("选择分组后加载词典。")]);
    const dictionaryAddForm = node("form", { className: "inline-form" });
    const dictionaryText = node("input", { type: "text", placeholder: "敏感词" });
    const dictionaryKind = node("input", { type: "text", value: "custom", placeholder: "person_name / person / custom" });
    const dictionaryAlias = node("input", { type: "text", placeholder: "统一别名" });
    const dictionaryAdd = formButton("添加", "button secondary");
    dictionaryAddForm.append(dictionaryText, dictionaryKind, dictionaryAlias, dictionaryAdd);
    const dictionaryStatus = statusBox();
    const dictionarySave = button("保存分组词典", async () => {
      const group = groupSelect.value || this.state.selectedGroupId;
      if (!group) return;
      dictionarySave.disabled = true;
      try {
        const entries = [...dictionaryList.querySelectorAll(".dictionary-row")].map((row) => ({
          text: row.querySelector("input[data-dictionary-text]")?.value.trim() || "",
          kind: row.querySelector("input[data-dictionary-kind]")?.value.trim() || "custom",
          alias: optionalAlias(row.querySelector("input[data-dictionary-alias]")?.value)
        })).filter((entry) => entry.text);
        await this.api.request(`/groups/${pathId(group)}/dictionary`, { method: "PUT", body: { entries } });
        setStatus(dictionaryStatus, "分组词典已保存。", "success");
        await this.loadDictionary(group, dictionaryList, dictionaryStatus);
      } catch (error) {
        setStatus(dictionaryStatus, apiErrorMessage(error), "danger");
      } finally {
        dictionarySave.disabled = false;
      }
    }, "button secondary");
    dictionaryAddForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const text = dictionaryText.value.trim();
      if (!text) return;
      dictionaryList.append(this.dictionaryRow({ text, kind: dictionaryKind.value.trim() || "custom", alias: dictionaryAlias.value.trim() }));
      dictionaryText.value = "";
      dictionaryAlias.value = "";
      setStatus(dictionaryStatus, "词典条目已加入待保存列表。", "success");
    });
    dictionaryPanel.append(dictionaryList, dictionaryAddForm, dictionarySave, dictionaryStatus);
    const importPanel = panel("导入材料");
    const importForm = node("form", { className: "stack-form" });
    const fileInput = node("input", { type: "file", accept: ".txt,.docx", multiple: true, required: true });
    const encodingSelect = node("select");
    appendOption(encodingSelect, "", "自动判断 TXT 编码");
    appendOption(encodingSelect, "utf-8", "UTF-8");
    appendOption(encodingSelect, "gb18030", "GB18030");
    const importButton = formButton("开始脱敏", "button primary");
    const importStatus = statusBox("支持 TXT、DOCX；不处理 PDF 和图片。", "muted");
    importForm.append(labelFor("选择文件", fileInput), fieldSelect("TXT 编码（可选）", { children: [] }));
    const encodingLabel = importForm.lastChild;
    encodingLabel.replaceChildren(node("span", { text: "TXT 编码（可选）" }), encodingSelect);
    importForm.append(importButton, importStatus);
    importForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const group = groupSelect.value || this.state.selectedGroupId;
      if (!group || !fileInput.files?.length) {
        setStatus(importStatus, "请选择材料分组和至少一个文件。", "warning");
        return;
      }
      importButton.disabled = true;
      setStatus(importStatus, "正在上传并创建任务…");
      const formData = new FormData();
      formData.set("group_id", group);
      formData.set("request_id", globalThis.crypto?.randomUUID?.() || `web-${Date.now()}-${Math.random().toString(16).slice(2)}`);
      if (encodingSelect.value) formData.set("encoding", encodingSelect.value);
      for (const file of fileInput.files) formData.append("files", file, file.name);
      try {
        const result = await this.api.request("/imports", { method: "POST", body: formData });
        const taskId = textValue(field(result, ["task_id", "taskId", "id"]));
        setStatus(importStatus, taskId ? `任务已创建：${taskId}` : "任务已创建，正在刷新材料列表。", "success");
        await this.loadPrivacyData(groupSelect, materialsList, detail, dictionaryList, dictionaryStatus);
        if (taskId) this.pollTask(taskId, importStatus, groupSelect, materialsList, detail);
      } catch (error) {
        setStatus(importStatus, apiErrorMessage(error), "danger");
      } finally {
        importButton.disabled = false;
      }
    });
    importPanel.append(importForm);
    const materialsPanel = panel("材料列表", [], "panel materials-panel");
    const materialsList = node("div", { className: "materials-list" }, [emptyState("正在加载分组…")]);
    materialsPanel.append(materialsList);
    left.append(groupPanel, dictionaryPanel, importPanel, materialsPanel);

    const detail = node("div", { className: "detail-area" });
    right.append(detail);
    await this.loadPrivacyData(groupSelect, materialsList, detail, dictionaryList, dictionaryStatus);
  }

  dictionaryRow(entry) {
    const text = node("input", { type: "text", value: textValue(entry?.text), ariaLabel: "词典敏感词" });
    text.dataset.dictionaryText = "true";
    const kind = node("input", { type: "text", value: textValue(entry?.kind, "custom"), ariaLabel: "词典类别" });
    kind.dataset.dictionaryKind = "true";
    const alias = node("input", { type: "text", value: textValue(entry?.alias), placeholder: "可留空自动生成", ariaLabel: "词典别名" });
    alias.dataset.dictionaryAlias = "true";
    let row;
    const remove = button("删除", () => row.remove(), "button subtle");
    row = node("div", { className: "dictionary-row" }, [text, kind, alias, remove]);
    return row;
  }

  async loadDictionary(groupIdValue, target, status) {
    if (!target) return;
    if (!groupIdValue) {
      replaceChildren(target, [emptyState("请选择分组后加载词典。")]);
      return;
    }
    try {
      const response = await this.api.request(`/groups/${pathId(groupIdValue)}/dictionary`);
      const entries = parseJsonList(response?.entries);
      replaceChildren(target, entries.length ? entries.map((entry) => this.dictionaryRow(entry)) : [emptyState("当前分组没有自定义词典。")]);
    } catch (error) {
      replaceChildren(target, [statusBox(apiErrorMessage(error), "danger")]);
      setStatus(status, apiErrorMessage(error), "danger");
    }
  }

  async loadPrivacyData(groupSelect, materialsList, detail, dictionaryList, dictionaryStatus) {
    try {
      const result = await this.api.request("/groups");
      this.state.groups = parseJsonList(result?.groups);
      replaceChildren(groupSelect);
      if (!this.state.groups.length) {
        appendOption(groupSelect, "", "暂无分组，请先新建");
        this.state.selectedGroupId = "";
        this.state.materials = [];
        replaceChildren(materialsList, [emptyState("请先创建材料分组。")]);
        replaceChildren(detail, [emptyState("选择材料后在这里复核。")]);
        if (dictionaryList) replaceChildren(dictionaryList, [emptyState("请先创建材料分组。")]);
        return;
      }
      const preferred = this.state.selectedGroupId && this.state.groups.some((group) => groupId(group) === this.state.selectedGroupId)
        ? this.state.selectedGroupId
        : groupId(this.state.groups[0]);
      this.state.selectedGroupId = preferred;
      for (const group of this.state.groups) appendOption(groupSelect, groupId(group), textValue(field(group, ["name", "title"]), "未命名分组"), groupId(group) === preferred);
      groupSelect.onchange = () => {
        this.state.selectedGroupId = groupSelect.value;
        this.state.selectedMaterial = null;
        this.loadPrivacyMaterials(groupSelect, materialsList, detail);
        this.loadDictionary(groupSelect.value, dictionaryList, dictionaryStatus);
      };
      await this.loadPrivacyMaterials(groupSelect, materialsList, detail);
      await this.loadDictionary(preferred, dictionaryList, dictionaryStatus);
    } catch (error) {
      replaceChildren(materialsList, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  async loadPrivacyMaterials(groupSelect, materialsList, detail) {
    if (!groupSelect.value) return;
    replaceChildren(materialsList, [emptyState("正在加载材料…")]);
    try {
      const response = await this.api.request(`/materials${queryString({ group_id: groupSelect.value })}`);
      this.state.materials = parseJsonList(response?.materials);
      const rows = [];
      for (const material of this.state.materials) {
        const id = textValue(field(material, ["id", "materialId", "material_id"]));
        const checkbox = node("input", { type: "checkbox", ariaLabel: `选择${materialName(material)}` });
        checkbox.dataset.materialId = id;
        const label = node("label", { className: "material-row" }, [
          checkbox,
          node("span", { className: "material-name", text: materialName(material) }),
          node("span", { className: `status-pill ${materialStatusTone(material.status)}`, text: statusLabel(material.status) })
        ]);
        label.append(node("span", { className: "material-meta", text: textValue(field(material, ["reason_code", "reasonCode"])) }));
        const openButton = button("查看", () => this.loadMaterialDetail(id, detail), "button subtle");
        const row = node("div", { className: "material-item" }, [label, openButton]);
        rows.push(row);
      }
      if (!rows.length) rows.push(emptyState("当前分组还没有材料。"));
      const exportBar = node("div", { className: "list-actions" });
      const format = node("select", { ariaLabel: "批量导出格式" });
      appendOption(format, "zip", "批量导出 ZIP");
      const exportButton = button("导出已选", async () => {
        const materialIds = [...materialsList.querySelectorAll("input[data-material-id]:checked")].map((input) => input.dataset.materialId).filter(Boolean);
        if (!materialIds.length) return;
        exportButton.disabled = true;
        try {
          const blob = await this.api.download("/exports", { method: "POST", body: { material_ids: materialIds, format: format.value } });
          await downloadBlob(blob, "律师助手脱敏材料.zip");
        } catch (error) {
          const message = statusBox(apiErrorMessage(error), "danger");
          materialsList.prepend(message);
        } finally {
          exportButton.disabled = false;
        }
      }, "button secondary");
      exportBar.append(format, exportButton);
      replaceChildren(materialsList, [exportBar, ...rows]);
      if (this.state.selectedMaterial) await this.loadMaterialDetail(textValue(field(this.state.selectedMaterial, ["id", "materialId"])), detail);
      else replaceChildren(detail, [emptyState("选择材料后在这里复核。")]);
    } catch (error) {
      replaceChildren(materialsList, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  async loadMaterialDetail(id, detail) {
    if (!id) return;
    replaceChildren(detail, [emptyState("正在加载材料详情…")]);
    try {
      const material = await this.api.request(`/materials/${pathId(id)}`);
      this.state.selectedMaterial = material;
      this.renderMaterialDetail(material, detail);
    } catch (error) {
      replaceChildren(detail, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  renderMaterialDetail(material, detail) {
    const id = textValue(field(material, ["id", "materialId"]));
    const revision = field(material, ["revision"], "");
    const title = node("div", { className: "detail-heading" }, [
      heading(2, materialName(material)),
      node("span", { className: `status-pill ${materialStatusTone(material.status)}`, text: statusLabel(material.status) })
    ]);
    const actions = node("div", { className: "button-row" });
    const result = resultId(material);
    for (const format of ["txt", "md", "docx"]) {
      const exportButton = button(`下载 ${format.toUpperCase()}`, async () => {
        exportButton.disabled = true;
        try {
          const blob = await this.api.download(`/results/${pathId(result)}/export${queryString({ format })}`);
          await downloadBlob(blob, safeFilename(materialName(material), format));
        } catch (error) {
          setStatus(detailStatus, apiErrorMessage(error), "danger");
        } finally {
          exportButton.disabled = false;
        }
      }, "button secondary");
      exportButton.disabled = !result || !["ready", "completed"].includes(String(material.status).toLowerCase());
      actions.append(exportButton);
    }
    const revokeButton = button("撤销结果", async () => {
      if (!window.confirm("撤销后该结果将不能通过 MCP 读取，是否继续？")) return;
      revokeButton.disabled = true;
      try {
        await this.api.request(`/materials/${pathId(id)}/revoke`, { method: "POST", body: {} });
        await this.loadMaterialDetail(id, detail);
      } catch (error) {
        setStatus(detailStatus, apiErrorMessage(error), "danger");
        revokeButton.disabled = false;
      }
    }, "button danger");
    revokeButton.disabled = !result;
    actions.append(revokeButton);
    const replacePanel = panel("替换源文件并重新处理", [], "panel replace-panel");
    const replaceForm = node("form", { className: "stack-form" });
    const replacementFile = node("input", { type: "file", accept: ".txt,.docx", required: true });
    const replacementEncoding = node("select");
    appendOption(replacementEncoding, "", "自动判断 TXT 编码");
    appendOption(replacementEncoding, "utf-8", "UTF-8");
    appendOption(replacementEncoding, "gb18030", "GB18030");
    appendOption(replacementEncoding, "utf-16", "UTF-16");
    appendOption(replacementEncoding, "utf-16le", "UTF-16LE");
    appendOption(replacementEncoding, "utf-16be", "UTF-16BE");
    const replaceButton = formButton("上传并重新处理", "button secondary");
    const replaceStatus = statusBox("适用于处理失败或需要重新指定 TXT 编码的材料。", "muted");
    replaceForm.append(labelFor("新的 TXT/DOCX 源文件", replacementFile), labelFor("TXT 编码（可选）", replacementEncoding), replaceButton, replaceStatus);
    replaceForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const file = replacementFile.files?.[0];
      if (!file) {
        setStatus(replaceStatus, "请选择一个 TXT 或 DOCX 文件。", "warning");
        return;
      }
      replaceButton.disabled = true;
      setStatus(replaceStatus, "正在替换源文件并创建新版本…");
      const formData = new FormData();
      formData.set("revision", String(revision));
      if (replacementEncoding.value) formData.set("encoding", replacementEncoding.value);
      formData.set("file", file, file.name);
      try {
        const response = await this.api.request(`/materials/${pathId(id)}/replace`, { method: "POST", body: formData });
        const responseId = textValue(field(response, ["id", "materialId", "material_id"]), id);
        const responseTaskId = textValue(field(response, ["task_id", "taskId"]));
        setStatus(replaceStatus, responseTaskId ? "源文件已替换，正在重新处理。" : "源文件已替换。", "success");
        await this.loadMaterialDetail(responseId, detail);
        if (responseTaskId && !textValue(field(this.state.selectedMaterial, ["task_id", "taskId"]))) {
          this.pollTask(responseTaskId, replaceStatus, null, null, detail);
        }
      } catch (error) {
        setStatus(replaceStatus, apiErrorMessage(error), "danger");
        replaceButton.disabled = false;
      }
    });
    const analysis = field(material, ["analysis"], {});
    const findings = parseJsonList(analysis?.findings);
    const hasAnalysis = Boolean(analysis && typeof analysis === "object" && ("text" in analysis || "findings" in analysis || "needsReview" in analysis));
    const analysisNeedsReview = analysis?.needsReview === true;
    const analysisNotice = !hasAnalysis
      ? statusBox("等待本地分析结果。", "muted")
      : analysisNeedsReview
      ? statusBox("自动检查标记为待复核；保存复核后才会重新发布结果。", "warning")
      : statusBox("当前识别结果已通过本地分析。", "success");
    const original = node("pre", { className: "source-text", text: textValue(material.original_text, "原文尚未提取或不可用。") });
    const sourceDetails = node("details", { className: "source-disclosure" }, [node("summary", { text: "查看已导入原文（仅本机）" }), original]);
    const redactedText = node("pre", { className: "redacted-text", text: textValue(analysis?.text, "脱敏文本尚未生成。") });
    const reviewForm = node("form", { className: "review-form" });
    const findingRows = [];
    const dictionary = [];
    for (const finding of findings) {
      const text = textValue(field(finding, ["text", "value"]));
      const kind = textValue(field(finding, ["kind", "type"]), "other");
      const alias = node("input", { type: "text", value: textValue(field(finding, ["alias"])) });
      const dismissed = node("input", { type: "checkbox", checked: Boolean(finding.dismissed || finding.resolved) });
      const row = node("div", { className: "finding-row" }, [
        node("span", { className: "finding-text", text }),
        node("span", { className: "finding-kind", text: kind }),
        labelFor("替换为", alias),
        labelFor("忽略", dismissed)
      ]);
      findingRows.push({ finding, text, kind, alias, dismissed });
      reviewForm.append(row);
      if (text) dictionary.push({ text, kind, alias: alias.value });
    }
    if (!findingRows.length) reviewForm.append(emptyState("没有检测到待处理项目。"));
    const extraText = node("input", { type: "text", placeholder: "补充需要脱敏的词语" });
    const extraKind = node("input", { type: "text", value: "custom", placeholder: "custom / person / person_name" });
    const extraAlias = node("input", { type: "text", placeholder: "留空自动生成，如 [PERSON_x]" });
    const addRow = node("div", { className: "finding-row add-finding" }, [labelFor("补充词语", extraText), labelFor("类别（支持 person 等别名）", extraKind), labelFor("替换别名（可留空）", extraAlias)]);
    reviewForm.append(addRow);
    const reviewButton = formButton("保存复核并重新检查", "button primary");
    const detailStatus = statusBox();
    reviewForm.append(reviewButton, detailStatus);
    reviewForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      reviewButton.disabled = true;
      const entries = findingRows.filter((row) => row.text && !row.dismissed.checked).map((row) => ({ text: row.text, kind: row.kind, alias: optionalAlias(row.alias.value) }));
      if (extraText.value.trim()) entries.push({ text: extraText.value.trim(), kind: extraKind.value.trim() || "custom", alias: optionalAlias(extraAlias.value) });
      const dismissed = findingRows.filter((row) => row.dismissed.checked).map((row) => textValue(field(row.finding, ["id", "findingId"]))).filter(Boolean);
      try {
        await this.api.request(`/materials/${pathId(id)}/review`, { method: "POST", body: { revision, dictionary: entries, dismissed } });
        setStatus(detailStatus, "已保存，材料将重新检查。", "success");
        await this.loadMaterialDetail(id, detail);
      } catch (error) {
        setStatus(detailStatus, apiErrorMessage(error), "danger");
        reviewButton.disabled = false;
      }
    });
    const taskId = textValue(field(material, ["task_id", "taskId"]));
    const taskPanel = node("div", { className: "task-panel" });
    if (taskId) this.renderTaskControls(taskId, taskPanel, detail);
    const detailStatusAndReview = node("div", { className: "review-panel" }, [heading(3, "检测结果与复核"), analysisNotice, reviewForm]);
    replaceChildren(detail, [title, actions, replacePanel, sourceDetails, heading(3, "脱敏预览"), redactedText, taskPanel, detailStatusAndReview]);
    replacePanel.append(replaceForm);
  }

  renderTaskControls(taskId, container, detail) {
    const text = statusBox("正在读取任务状态…");
    const controls = node("div", { className: "button-row" });
    const cancel = button("取消任务", async () => {
      cancel.disabled = true;
      try {
        await this.api.request(`/tasks/${pathId(taskId)}/cancel`, { method: "POST", body: {} });
        setStatus(text, "任务已取消。", "warning");
      } catch (error) {
        setStatus(text, apiErrorMessage(error), "danger");
        cancel.disabled = false;
      }
    }, "button subtle");
    const retry = button("重试任务", async () => {
      retry.disabled = true;
      try {
        await this.api.request(`/tasks/${pathId(taskId)}/retry`, { method: "POST", body: {} });
        setStatus(text, "已提交重试。", "success");
        this.pollTask(taskId, text, null, null, detail);
      } catch (error) {
        setStatus(text, apiErrorMessage(error), "danger");
        retry.disabled = false;
      }
    }, "button secondary");
    const consentForm = node("form", { className: "consent-form" });
    const provider = node("select");
    appendOption(provider, "", "选择已配置的模型服务");
    this.loadProvidersInto(provider);
    const model = node("input", { type: "text", placeholder: "模型名称", required: true });
    const consent = formButton("授权本批次云辅助", "button secondary");
    const revokeConsent = button("撤销云辅助授权", async () => {
      revokeConsent.disabled = true;
      try {
        await this.api.request(`/tasks/${pathId(taskId)}/consent`, { method: "DELETE" });
        setStatus(text, "云辅助授权已撤销，未发送新的材料。", "warning");
      } catch (error) {
        setStatus(text, apiErrorMessage(error), "danger");
        revokeConsent.disabled = false;
      }
    }, "button subtle");
    consentForm.append(provider, model, consent);
    consentForm.append(revokeConsent);
    consentForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      consent.disabled = true;
      try {
        await this.api.request(`/tasks/${pathId(taskId)}/consent`, { method: "POST", body: { provider_id: provider.value, model: model.value.trim(), purpose: "redaction_assistance" } });
        setStatus(text, "本批次云辅助已授权。", "success");
        this.pollTask(taskId, text, null, null, detail);
      } catch (error) {
        setStatus(text, apiErrorMessage(error), "danger");
      } finally {
        consent.disabled = false;
      }
    });
    controls.append(cancel, retry);
    container.append(heading(3, "任务状态"), text, controls, consentForm);
    this.pollTask(taskId, text, null, null, detail);
  }

  async loadProvidersInto(select) {
    try {
      const response = await this.api.request("/providers");
      this.state.providers = parseJsonList(response?.providers);
      for (const provider of this.state.providers) appendOption(select, textValue(field(provider, ["id"])), textValue(field(provider, ["name"]), "未命名服务"));
    } catch {
      appendOption(select, "", "暂无可用模型服务");
    }
  }

  pollTask(taskId, status, groupSelect, materialsList, detail) {
    if (this.state.taskTimer) clearTimeout(this.state.taskTimer);
    const poll = async () => {
      try {
        const task = await this.api.request(`/tasks/${pathId(taskId)}`);
        const taskStatus = textValue(field(task, ["status"]));
        setStatus(status, `任务：${statusLabel(taskStatus)}`, materialStatusTone(taskStatus));
        const done = ["completed", "failed", "cancelled", "ready", "partial", "needs_review", "awaiting_consent"].includes(taskStatus.toLowerCase());
        if (!done) {
          this.state.taskTimer = setTimeout(poll, 1500);
        } else if (groupSelect && materialsList && detail) {
          await this.loadPrivacyData(groupSelect, materialsList, detail);
        } else if (detail && this.state.selectedMaterial) {
          const selectedId = textValue(field(this.state.selectedMaterial, ["id", "materialId"]));
          if (selectedId) await this.loadMaterialDetail(selectedId, detail);
        }
      } catch (error) {
        setStatus(status, apiErrorMessage(error), "danger");
      }
    };
    poll();
  }

  async renderLegal(main) {
    const title = node("div", { className: "page-title" }, [heading(1, "法律检索"), node("p", { text: "查询本地法律库，查看条文、历史版本和关联法规。" })]);
    const layout = node("div", { className: "workspace-grid legal-grid" });
    const searchColumn = node("div", { className: "workspace-column" });
    const detailColumn = node("div", { className: "workspace-column" });
    layout.append(searchColumn, detailColumn);
    main.append(title, layout);
    const searchPanel = panel("搜索法律库");
    const searchForm = node("form", { className: "search-form" });
    const query = node("input", { type: "search", placeholder: "输入法条、关键词或文号", required: true });
    const caseDate = node("input", { type: "date" });
    const searchButton = formButton("搜索", "button primary");
    searchForm.append(labelFor("关键词", query), labelFor("案件日期（可选）", caseDate), searchButton);
    const searchStatus = statusBox();
    searchPanel.append(searchForm, searchStatus);
    const resultsPanel = panel("搜索结果", [], "panel results-panel");
    const results = node("div", { className: "legal-results" }, [emptyState("输入关键词开始搜索。")]);
    resultsPanel.append(results);
    const bookmarksPanel = panel("我的收藏", [], "panel bookmarks-panel");
    const bookmarks = node("div", { className: "bookmark-list" }, [emptyState("正在加载收藏…")]);
    bookmarksPanel.append(bookmarks);
    searchColumn.append(searchPanel, resultsPanel, bookmarksPanel);
    const detail = node("div", { className: "detail-area" }, [emptyState("选择一条法规查看详情。")]);
    detailColumn.append(detail);
    searchForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      searchButton.disabled = true;
      setStatus(searchStatus, "正在查询…");
      try {
        const response = await this.api.request(`/legal/search${queryString({ query: query.value, case_date: caseDate.value })}`);
        this.state.legalResults = responseList(response, ["articles", "results", "items"]);
        this.renderLegalResults(this.state.legalResults, results, detail);
        setStatus(searchStatus, `找到 ${this.state.legalResults.length} 条结果。`, "success");
      } catch (error) {
        replaceChildren(results, [statusBox(apiErrorMessage(error), "danger")]);
        setStatus(searchStatus, apiErrorMessage(error), "danger");
      } finally {
        searchButton.disabled = false;
      }
    });
    await this.loadBookmarks(bookmarks);
  }

  renderLegalResults(items, target, detail) {
    if (!items.length) {
      replaceChildren(target, [emptyState("没有找到匹配条文。")]);
      return;
    }
    const rows = items.map((article) => {
      const id = articleId(article);
      const title = legalArticleDisplayTitle(article);
      const source = textValue(field(article, ["documentTitle", "document_title"]));
      const effective = textValue(field(article, ["effectiveFrom", "effective_from"]));
      const status = textValue(field(article, ["versionStatus", "version_status"]));
      const buttonNode = button(title, () => this.loadArticle(id, detail), "result-button");
      const metadata = node("p", { className: "result-meta", text: [source, effective ? `生效：${effective}` : "", status ? `状态：${status}` : ""].filter(Boolean).join(" · ") });
      return node("article", { className: "result-card" }, [buttonNode, metadata]);
    });
    replaceChildren(target, rows);
  }

  async loadArticle(id, detail) {
    if (!id) return;
    replaceChildren(detail, [emptyState("正在加载条文…")]);
    try {
      const response = await this.api.request(`/legal/articles/${pathId(id)}`);
      const article = response?.article && typeof response.article === "object" ? response.article : response;
      this.state.selectedArticle = article;
      this.renderArticleDetail(article, detail);
    } catch (error) {
      replaceChildren(detail, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  renderArticleDetail(article, detail) {
    const id = articleId(article);
    const documentId = legalArticleDocumentId(article);
    const title = legalArticleDisplayTitle(article);
    const content = textValue(field(article, ["content", "text", "body", "articleText"]), "暂无正文。");
    const source = textValue(field(article, ["documentTitle", "document_title"]));
    const effective = textValue(field(article, ["effectiveFrom", "effective_from"]));
    const status = textValue(field(article, ["versionStatus", "version_status"]));
    const headingBlock = node("div", { className: "detail-heading" }, [heading(2, title), node("p", { className: "muted", text: [source, effective ? `生效：${effective}` : "", status ? `状态：${status}` : ""].filter(Boolean).join(" · ") })]);
    const actions = node("div", { className: "button-row" });
    const bookmark = button("收藏条文", async () => {
      bookmark.disabled = true;
      try {
        await this.api.request("/bookmarks", { method: "POST", body: { article_id: id, title } });
        bookmark.textContent = "已收藏";
      } catch (error) {
        bookmark.textContent = apiErrorMessage(error);
        bookmark.disabled = false;
      }
    }, "button secondary");
    const copy = button("复制引用", async () => {
      try {
        await copyText(textValue(field(article, ["canonicalLabel", "canonical_label"]), `${title}${source ? `（${source}）` : ""}`));
        copy.textContent = "已复制";
        setTimeout(() => { copy.textContent = "复制引用"; }, 1500);
      } catch {
        copy.textContent = "浏览器不支持复制";
      }
    }, "button secondary");
    const versions = button("查看历史版本", async () => {
      versions.disabled = true;
      try {
        const response = await this.api.request(`/legal/versions/${pathId(documentId)}`);
        const items = responseList(response, ["versions", "items"]);
        replaceChildren(versionBox, [heading(3, "历史版本"), ...(items.length ? items.map((version) => node("p", { className: "version-item", text: [textValue(field(version, ["versionLabel", "version_label"]), "版本"), textValue(field(version, ["status"])), textValue(field(version, ["effectiveFrom", "effective_from", "date"]), "日期未知"), textValue(field(version, ["effectiveTo", "effective_to"]), "")].filter(Boolean).join(" · ") })) : [emptyState("没有历史版本记录。")])]);
      } catch (error) {
        replaceChildren(versionBox, [statusBox(apiErrorMessage(error), "danger")]);
      } finally {
        versions.disabled = false;
      }
    }, "button subtle");
    const relations = button("查看关联法规", async () => {
      relations.disabled = true;
      try {
        const response = await this.api.request(`/legal/relations/${pathId(documentId)}`);
        const items = responseList(response, ["relations", "items"]);
        replaceChildren(relationBox, [heading(3, "关联法规"), ...(items.length ? items.map((related) => {
          const target = legalRelationTarget(related, documentId);
          const relationText = [textValue(field(related, ["relationType", "relation_type"])), textValue(field(related, ["description"])), textValue(field(related, ["sourceReference", "source_reference"]))].filter(Boolean).join(" · ");
          const targetButton = button(target.title, () => this.loadArticle(target.documentId, detail), "link-button");
          return node("div", { className: "version-item" }, [targetButton, relationText ? node("p", { className: "result-meta", text: relationText }) : null]);
        }) : [emptyState("没有关联法规记录。")])]);
      } catch (error) {
        replaceChildren(relationBox, [statusBox(apiErrorMessage(error), "danger")]);
      } finally {
        relations.disabled = false;
      }
    }, "button subtle");
    actions.append(bookmark, copy, versions, relations);
    const text = node("pre", { className: "legal-text", text: content });
    const versionBox = node("div", { className: "related-box" });
    const relationBox = node("div", { className: "related-box" });
    replaceChildren(detail, [headingBlock, actions, text, versionBox, relationBox]);
  }

  async loadBookmarks(target) {
    try {
      const response = await this.api.request("/bookmarks");
      this.state.legalBookmarks = parseJsonList(response?.bookmarks);
      if (!this.state.legalBookmarks.length) {
        replaceChildren(target, [emptyState("还没有收藏条文。")]);
        return;
      }
      const rows = this.state.legalBookmarks.map((bookmark) => {
        const id = textValue(field(bookmark, ["id", "bookmarkId"]));
        const article = textValue(field(bookmark, ["article_id", "articleId"]));
        const title = textValue(field(bookmark, ["title"]), "未命名条文");
        const remove = button("移除", async () => {
          remove.disabled = true;
          try {
            await this.api.request(`/bookmarks/${pathId(id)}`, { method: "DELETE" });
            await this.loadBookmarks(target);
          } catch (error) {
            remove.disabled = false;
            target.prepend(statusBox(apiErrorMessage(error), "danger"));
          }
        }, "button subtle");
        return node("div", { className: "bookmark-row" }, [node("span", { text: title }), node("span", { className: "muted small", text: article }), remove]);
      });
      replaceChildren(target, rows);
    } catch (error) {
      replaceChildren(target, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  async renderTemplates(main) {
    const title = node("div", { className: "page-title" }, [heading(1, "文书模板"), node("p", { text: "使用固定模板填写常用信息，预览后导出 TXT、Markdown 或 DOCX。" })]);
    const layout = node("div", { className: "workspace-grid template-grid" });
    const editorColumn = node("div", { className: "workspace-column" });
    const previewColumn = node("div", { className: "workspace-column" });
    layout.append(editorColumn, previewColumn);
    main.append(title, layout);
    const editor = panel("填写模板");
    const form = node("form", { className: "stack-form" });
    const templateSelect = node("select", { required: true });
    appendOption(templateSelect, "", "正在加载模板…");
    const values = {};
    const fields = [
      ["title", "文书标题", "请输入文书标题"],
      ["party_a", "当事人甲", ""],
      ["party_b", "当事人乙", ""],
      ["facts", "事实与理由", "请填写事实经过"],
      ["requests", "请求事项", ""],
      ["evidence", "证据材料", ""],
      ["requirements", "其他要求", ""]
    ];
    form.append(labelFor("模板", templateSelect));
    for (const [key, label, placeholder] of fields) {
      const control = key === "title" || key === "party_a" || key === "party_b"
        ? node("input", { type: "text", placeholder })
        : node("textarea", { rows: key === "facts" ? 6 : 3, placeholder });
      values[key] = control;
      form.append(labelFor(label, control));
    }
    const previewButton = formButton("生成预览", "button primary");
    const status = statusBox();
    form.append(previewButton, status);
    editor.append(form);
    editorColumn.append(editor);
    const previewPanel = panel("预览", [], "panel preview-panel");
    const preview = node("pre", { className: "document-preview", text: "填写信息并生成预览。" });
    const exportRow = node("div", { className: "button-row" });
    const format = node("select");
    appendOption(format, "txt", "TXT");
    appendOption(format, "md", "Markdown");
    appendOption(format, "docx", "DOCX");
    const exportButton = button("导出", async () => {
      if (!preview.textContent || preview.textContent === "填写信息并生成预览。") return;
      exportButton.disabled = true;
      try {
        const blob = await this.api.download("/templates/export", { method: "POST", body: { template_id: templateSelect.value, input: this.templateInput(values), format: format.value } });
        await downloadBlob(blob, safeFilename(values.title.value || "文书", format.value));
      } catch (error) {
        setStatus(status, apiErrorMessage(error), "danger");
      } finally {
        exportButton.disabled = false;
      }
    }, "button secondary");
    exportRow.append(format, exportButton);
    previewPanel.append(preview, exportRow);
    previewColumn.append(previewPanel);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      previewButton.disabled = true;
      setStatus(status, "正在生成预览…");
      try {
        const response = await this.api.request("/templates/preview", { method: "POST", body: { template_id: templateSelect.value, input: this.templateInput(values) } });
        preview.textContent = textValue(response?.text, "暂无预览内容。");
        setStatus(status, "预览已生成。", "success");
      } catch (error) {
        setStatus(status, apiErrorMessage(error), "danger");
      } finally {
        previewButton.disabled = false;
      }
    });
    try {
      const response = await this.api.request("/templates");
      this.state.templates = parseJsonList(response?.templates);
      replaceChildren(templateSelect);
      if (!this.state.templates.length) appendOption(templateSelect, "", "暂无可用模板");
      for (const template of this.state.templates) appendOption(templateSelect, templateId(template), templateTitle(template));
    } catch (error) {
      replaceChildren(templateSelect, [node("option", { value: "", text: "模板加载失败" })]);
      setStatus(status, apiErrorMessage(error), "danger");
    }
  }

  templateInput(values) {
    return Object.fromEntries(Object.entries(values).map(([key, input]) => [key, input.value]));
  }

  async renderChat(main) {
    const title = node("div", { className: "page-title" }, [heading(1, "AI 对话"), node("p", { text: "只将你明确选择的脱敏结果和法条作为上下文发送给模型。" })]);
    const layout = node("div", { className: "workspace-grid chat-grid" });
    const conversationsColumn = node("div", { className: "workspace-column" });
    const chatColumn = node("div", { className: "workspace-column" });
    layout.append(conversationsColumn, chatColumn);
    main.append(title, layout);
    const conversationsPanel = panel("会话");
    const createForm = node("form", { className: "inline-form" });
    const conversationTitle = node("input", { type: "text", placeholder: "新会话标题", required: true });
    const createButton = formButton("新建", "button secondary");
    createForm.append(conversationTitle, createButton);
    const conversationStatus = statusBox();
    const conversationList = node("div", { className: "conversation-list" }, [emptyState("正在加载会话…")]);
    conversationsPanel.append(createForm, conversationStatus, conversationList);
    conversationsColumn.append(conversationsPanel);
    const chatPanel = panel("对话", [], "panel chat-panel");
    const providerSelect = node("select");
    appendOption(providerSelect, "", "选择模型服务");
    await this.loadProvidersInto(providerSelect);
    const messages = node("div", { className: "message-list", ariaLive: "polite" }, [emptyState("选择或新建会话。")]);
    const contextForm = node("form", { className: "context-form" });
    const resultIds = node("input", { type: "text", placeholder: "可选：脱敏结果 ID，逗号分隔" });
    const articleIds = node("input", { type: "text", placeholder: "可选：法条 ID，逗号分隔" });
    contextForm.append(labelFor("脱敏结果上下文", resultIds), labelFor("法条上下文", articleIds));
    const composer = node("form", { className: "composer" });
    const messageInput = node("textarea", { rows: 4, placeholder: "输入问题；原始材料不会自动加入上下文。", required: true });
    const sendButton = formButton("发送", "button primary");
    const cancelButton = button("取消生成", () => this.cancelChat(this.state.selectedConversation?.id, sendButton, cancelButton), "button subtle");
    cancelButton.disabled = true;
    const chatStatus = statusBox();
    composer.append(labelFor("消息", messageInput), node("div", { className: "button-row" }, [providerSelect, sendButton, cancelButton]), chatStatus);
    chatPanel.append(contextForm, messages, composer);
    chatColumn.append(chatPanel);
    createForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      createButton.disabled = true;
      try {
        const response = await this.api.request("/conversations", { method: "POST", body: { title: conversationTitle.value.trim() } });
        conversationTitle.value = "";
        setStatus(conversationStatus, "会话已创建。", "success");
        await this.loadConversations(conversationList, messages, response?.id);
      } catch (error) {
        setStatus(conversationStatus, apiErrorMessage(error), "danger");
      } finally {
        createButton.disabled = false;
      }
    });
    composer.addEventListener("submit", async (event) => {
      event.preventDefault();
      const conversationId = textValue(field(this.state.selectedConversation, ["id", "conversationId"]));
      if (!conversationId) {
        setStatus(chatStatus, "请先选择一个会话。", "warning");
        return;
      }
      if (!providerSelect.value) {
        setStatus(chatStatus, "请先选择模型服务。", "warning");
        return;
      }
      const text = messageInput.value.trim();
      if (!text) return;
      sendButton.disabled = true;
      cancelButton.disabled = false;
      messageInput.value = "";
      setStatus(chatStatus, "模型生成中…");
      const userMessage = { role: "user", content: text };
      const assistantMessage = { role: "assistant", content: "" };
      const existing = parseJsonList(this.state.selectedConversation?.messages);
      this.state.selectedConversation.messages = [...existing, userMessage, assistantMessage];
      this.renderMessages(messages, this.state.selectedConversation.messages);
      const abort = new AbortController();
      this.state.chatAbort = abort;
      try {
        await this.api.streamChat("/chat", {
          conversation_id: conversationId,
          provider_id: providerSelect.value,
          message: text,
          result_ids: splitIds(resultIds.value),
          article_ids: splitIds(articleIds.value)
        }, {
          signal: abort.signal,
          onDelta: (delta) => {
            assistantMessage.content += delta;
            this.renderMessages(messages, this.state.selectedConversation.messages);
          },
          onDone: () => setStatus(chatStatus, "生成完成。", "success"),
          onError: (error) => setStatus(chatStatus, apiErrorMessage(error), "danger")
        });
        await this.loadConversation(conversationId, messages);
      } catch (error) {
        if (error?.name === "AbortError") setStatus(chatStatus, "已取消生成。", "warning");
        else setStatus(chatStatus, apiErrorMessage(error), "danger");
      } finally {
        this.state.chatAbort = null;
        sendButton.disabled = false;
        cancelButton.disabled = true;
      }
    });
    await this.loadConversations(conversationList, messages);
  }

  renderMessages(target, items) {
    if (!items.length) {
      replaceChildren(target, [emptyState("还没有消息。")]);
      return;
    }
    replaceChildren(target, items.map((message) => {
      const role = textValue(message?.role) === "user" ? "user" : "assistant";
      return node("article", { className: `chat-message ${role}` }, [
        node("span", { className: "message-role", text: role === "user" ? "我" : "助手" }),
        node("pre", { className: "message-content", text: textValue(message?.content) })
      ]);
    }));
    target.lastElementChild?.scrollIntoView?.({ block: "nearest" });
  }

  async loadConversations(target, messages, preferredId = "") {
    try {
      const response = await this.api.request("/conversations");
      this.state.conversations = parseJsonList(response?.conversations);
      replaceChildren(target);
      if (!this.state.conversations.length) {
        target.append(emptyState("还没有会话。"));
        this.state.selectedConversation = null;
        replaceChildren(messages, [emptyState("选择或新建会话。")]);
        return;
      }
      const selectedId = preferredId || textValue(field(this.state.selectedConversation, ["id", "conversationId"])) || textValue(field(this.state.conversations[0], ["id", "conversationId"]));
      for (const conversation of this.state.conversations) {
        const id = textValue(field(conversation, ["id", "conversationId"]));
        const item = button(textValue(field(conversation, ["title", "name"]), "未命名会话"), () => this.loadConversation(id, messages), `conversation-item${id === selectedId ? " active" : ""}`);
        target.append(item);
      }
      await this.loadConversation(selectedId, messages);
    } catch (error) {
      replaceChildren(target, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  async loadConversation(id, messages) {
    if (!id) return;
    try {
      const conversation = await this.api.request(`/conversations/${pathId(id)}`);
      this.state.selectedConversation = conversation;
      this.renderMessages(messages, parseJsonList(conversation?.messages));
    } catch (error) {
      replaceChildren(messages, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  async cancelChat(id, sendButton, cancelButton) {
    if (this.state.chatAbort) this.state.chatAbort.abort();
    if (id) {
      try {
        await this.api.request(`/chat/${pathId(id)}`, { method: "DELETE" });
      } catch {
        // The local abort already stops the reader; a disconnected server can finish cancellation later.
      }
    }
    sendButton.disabled = false;
    cancelButton.disabled = true;
  }

  async renderSettings(main) {
    const title = node("div", { className: "page-title" }, [heading(1, "设置"), node("p", { text: "管理模型服务、MCP 客户端和本机运行状态。" })]);
    const layout = node("div", { className: "settings-grid" });
    const providerSection = panel("模型服务", [], "panel settings-panel");
    const mcpSection = panel("MCP 客户端", [], "panel settings-panel");
    const statusSection = panel("运行状态", [], "panel settings-panel");
    layout.append(providerSection, mcpSection, statusSection);
    main.append(title, layout);
    await this.renderProviders(providerSection);
    await this.renderMcpClients(mcpSection);
    this.renderRuntimeStatus(statusSection);
  }

  async renderProviders(target) {
    const list = node("div", { className: "provider-list" }, [emptyState("正在加载模型服务…")]);
    const form = node("form", { className: "provider-form" });
    const id = node("input", { type: "text", placeholder: "编辑时填写已有 ID（可选）" });
    const name = node("input", { type: "text", placeholder: "服务名称", required: true });
    const baseUrl = node("input", { type: "url", placeholder: "https://…", required: true });
    const model = node("input", { type: "text", placeholder: "模型名称", required: true });
    const apiKey = node("input", { type: "password", placeholder: "留空表示不修改密钥", autocomplete: "new-password" });
    const allowPrivateNetwork = node("input", { type: "checkbox", checked: false, ariaLabel: "允许访问私有网络" });
    const save = formButton("保存模型服务", "button primary");
    const status = statusBox();
    form.append(fieldInput("ID（编辑已有配置时填写）", id), fieldInput("名称", name), fieldInput("Base URL", baseUrl), fieldInput("模型", model), fieldInput("API Key", apiKey), labelFor("允许访问私有网络（默认关闭；本机 mock 联调时按需开启）", allowPrivateNetwork), save, status);
    target.append(list, form);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      save.disabled = true;
      try {
        const body = { name: name.value.trim(), base_url: baseUrl.value.trim(), model: model.value.trim(), allow_private_network: allowPrivateNetwork.checked };
        if (id.value.trim()) body.id = id.value.trim();
        if (apiKey.value) body.api_key = apiKey.value;
        await this.api.request("/providers", { method: "POST", body });
        apiKey.value = "";
        setStatus(status, "模型服务已保存。", "success");
        await this.refreshProviderList(list, (provider) => {
          id.value = textValue(field(provider, ["id"]));
          name.value = textValue(field(provider, ["name"]));
          baseUrl.value = textValue(field(provider, ["base_url", "baseUrl"]));
          model.value = textValue(field(provider, ["model"]));
          allowPrivateNetwork.checked = provider.allow_private_network === true;
          setStatus(status, "已载入配置；API Key 留空则保持原值。", "success");
        });
      } catch (error) {
        setStatus(status, apiErrorMessage(error), "danger");
      } finally {
        save.disabled = false;
      }
    });
    await this.refreshProviderList(list, (provider) => {
      id.value = textValue(field(provider, ["id"]));
      name.value = textValue(field(provider, ["name"]));
      baseUrl.value = textValue(field(provider, ["base_url", "baseUrl"]));
      model.value = textValue(field(provider, ["model"]));
      allowPrivateNetwork.checked = provider.allow_private_network === true;
      setStatus(status, "已载入配置；API Key 留空则保持原值。", "success");
    });
  }

  async refreshProviderList(target, onSelect) {
    try {
      const response = await this.api.request("/providers");
      this.state.providers = parseJsonList(response?.providers);
      if (!this.state.providers.length) {
        replaceChildren(target, [emptyState("尚未配置模型服务。")]);
        return;
      }
      replaceChildren(target, this.state.providers.map((provider) => {
        const edit = button("编辑", () => onSelect?.(provider), "button subtle");
        return node("div", { className: "provider-row" }, [
          node("strong", { text: textValue(field(provider, ["name"]), "未命名服务") }),
          node("span", { className: "muted small", text: `${textValue(field(provider, ["model"]), "未设置模型")} · API Key ${provider.key_configured ? "已配置" : "未配置"} · 私有网络 ${provider.allow_private_network ? "已允许" : "已关闭"}` }),
          edit
        ]);
      }));
    } catch (error) {
      replaceChildren(target, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  async renderMcpClients(target) {
    const list = node("div", { className: "mcp-list" }, [emptyState("正在加载 MCP 客户端…")]);
    const form = node("form", { className: "inline-form" });
    const name = node("input", { type: "text", placeholder: "客户端名称", required: true });
    const group = node("select", { required: true });
    appendOption(group, "", "选择材料分组");
    const create = formButton("创建客户端", "button secondary");
    const status = statusBox();
    form.append(name, group, create);
    target.append(list, form, status);
    try {
      const groups = await this.api.request("/groups");
      this.state.groups = parseJsonList(groups?.groups);
      replaceChildren(group);
      for (const item of this.state.groups) appendOption(group, groupId(item), textValue(field(item, ["name"]), "未命名分组"));
    } catch (error) {
      setStatus(status, apiErrorMessage(error), "danger");
    }
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      create.disabled = true;
      try {
        const response = await this.api.request("/mcp/clients", { method: "POST", body: { name: name.value.trim(), group_id: group.value } });
        const token = textValue(response?.token);
        this.state.pendingMcpToken = token || null;
        setStatus(status, token ? "客户端已创建。令牌只显示一次，请立即下载配置。" : "客户端已创建。", "success");
        if (token) this.renderMcpToken(target, token, response?.client);
        name.value = "";
        await this.refreshMcpList(list);
      } catch (error) {
        setStatus(status, apiErrorMessage(error), "danger");
      } finally {
        create.disabled = false;
      }
    });
    await this.refreshMcpList(list);
  }

  async copyMcpInbox(inbox, status) {
    if (!inbox) return;
    try {
      await copyText(inbox);
      setStatus(status, "收件目录已复制。", "success");
    } catch {
      setStatus(status, "当前浏览器不支持复制，请手动选中收件目录。", "warning");
    }
  }

  renderMcpToken(target, token, client = {}) {
    const existing = target.querySelector(".mcp-token-box");
    existing?.remove();
    const details = mcpClientDetails(client, this.state.groups);
    const copyStatus = statusBox();
    const copy = button("复制收件目录", () => this.copyMcpInbox(details.inbox, copyStatus), "button subtle");
    copy.disabled = !details.inbox;
    const inbox = node("div", { className: "mcp-inbox" }, [
      node("span", { className: "muted small", text: "收件目录" }),
      node("code", { className: "mcp-path", text: details.inbox || "后端未返回收件目录。" }),
      copy,
      copyStatus
    ]);
    const group = node("p", { className: "muted small", text: `材料分组：${details.groupName}（${details.groupId || "无 ID"}）` });
    const box = node("div", { className: "mcp-token-box" }, [heading(3, "新客户端令牌"), node("p", { className: "token-text", text: token }), node("p", { className: "muted small", text: "令牌只显示一次；收件目录用于放入待脱敏材料，请立即下载配置并妥善保管。" }), group, inbox]);
    const download = button("下载 MCP 配置", async () => {
      const payload = { mcp: { url: `${globalThis.location?.origin || ""}/api/v1/mcp`, token } };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
      await downloadBlob(blob, "lawyer-assistance-mcp.json");
      this.state.pendingMcpToken = null;
    }, "button secondary");
    box.append(download);
    target.prepend(box);
  }

  async refreshMcpList(target) {
    try {
      const response = await this.api.request("/mcp/clients");
      this.state.mcpClients = parseJsonList(response?.clients);
      if (!this.state.mcpClients.length) {
        replaceChildren(target, [emptyState("尚未创建 MCP 客户端。")]);
        return;
      }
      replaceChildren(target, this.state.mcpClients.map((client) => {
        const id = textValue(field(client, ["id"]));
        const details = mcpClientDetails(client, this.state.groups);
        const copyStatus = statusBox();
        const copy = button("复制目录", () => this.copyMcpInbox(details.inbox, copyStatus), "button subtle");
        copy.disabled = !details.inbox;
        const revoke = button("撤销", async () => {
          revoke.disabled = true;
          try {
            await this.api.request(`/mcp/clients/${pathId(id)}`, { method: "DELETE" });
            await this.refreshMcpList(target);
          } catch (error) {
            target.prepend(statusBox(apiErrorMessage(error), "danger"));
            revoke.disabled = false;
          }
        }, "button danger");
        const detailsPanel = node("div", { className: "mcp-details" }, [
          node("span", { className: "muted small", text: `${client.enabled === false ? "已停用" : "已启用"} · 分组：${details.groupName}（${details.groupId || "无 ID"}）` }),
          node("code", { className: "mcp-path", text: details.inbox || "后端未返回收件目录。" }),
          node("div", { className: "button-row" }, [copy, copyStatus])
        ]);
        return node("div", { className: "mcp-row" }, [node("strong", { text: textValue(field(client, ["name"]), "未命名客户端") }), detailsPanel, revoke]);
      }));
    } catch (error) {
      replaceChildren(target, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  renderRuntimeStatus(target) {
    const health = this.state.health;
    const rows = [
      ["服务", textValue(health?.status, "未知")],
      ["法律库", health?.legal_ready ? "已就绪" : "不可用"],
      ["版本", textValue(health?.version, "未知")],
      ["OCR", health?.ocr?.available ? "可用" : "未启用（首版范围外）"]
    ];
    target.append(node("dl", { className: "status-list" }, rows.flatMap(([label, value]) => [node("dt", { text: label }), node("dd", { text: value })])));
    target.append(node("p", { className: "muted small", text: "数据保存在后台服务配置的本机工作区；浏览器不会使用本地存储保存材料。" }));
  }
}

if (typeof document !== "undefined") {
  const root = document.getElementById("app");
  if (root) {
    const app = new WebApp(root);
    app.start();
  }
}
