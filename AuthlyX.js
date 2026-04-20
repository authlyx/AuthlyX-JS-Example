const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");
const childProcess = require("child_process");

class AuthlyXLogger {
  static Enabled = true;
  static AppName = "AuthlyX";

  static maskSensitive(input) {
    if (input === null || input === undefined) return "";
    let text = String(input);
    const patterns = [
      /("session_id"\s*:\s*")([^"]+)(")/gi,
      /("owner_id"\s*:\s*")([^"]+)(")/gi,
      /("secret"\s*:\s*")([^"]+)(")/gi,
      /("password"\s*:\s*")([^"]+)(")/gi,
      /("key"\s*:\s*")([^"]+)(")/gi,
      /("license_key"\s*:\s*")([^"]+)(")/gi,
      /("hash"\s*:\s*")([^"]+)(")/gi,
      /("request_id"\s*:\s*")([^"]+)(")/gi,
      /("nonce"\s*:\s*")([^"]+)(")/gi,
      /("hwid"\s*:\s*")([^"]+)(")/gi,
      /("sid"\s*:\s*")([^"]+)(")/gi,
      /(\bx-auth-signature\s*:\s*)([A-Za-z0-9+/=]+)/gi,
      /(\bx-v2-signature\s*:\s*)([A-Za-z0-9+/=]+)/gi
    ];
    for (const p of patterns) {
      text = text.replace(p, (_, a, __, c) => (c ? `${a}***${c}` : `${a}***`));
    }
    return text;
  }

  static log(content) {
    if (!AuthlyXLogger.Enabled) return;
    if (content === null || content === undefined) return;
    const s = String(content);
    if (!s.trim()) return;

    try {
      const app = (AuthlyXLogger.AppName || "default").trim() || "default";
      const programData = process.env.PROGRAMDATA || "";
      const root =
        process.platform === "win32" && programData
          ? path.join(programData, "AuthlyX", app)
          : path.join(os.homedir(), ".authlyx", app);
      fs.mkdirSync(root, { recursive: true });
      const file = path.join(root, `${new Date().toISOString().slice(0, 10).replace(/-/g, "_")}.log`);
      const now = new Date();
      const hh = String(now.getUTCHours()).padStart(2, "0");
      const mm = String(now.getUTCMinutes()).padStart(2, "0");
      const ss = String(now.getUTCSeconds()).padStart(2, "0");
      const line = `[${hh}:${mm}:${ss}] ${AuthlyXLogger.maskSensitive(s)}\n`;
      fs.appendFileSync(file, line, { encoding: "utf8" });
    } catch {
      return;
    }
  }
}

class AuthlyX {
  static DefaultBaseUrl = "https://authly.cc/api/v2";
  static IpLookupUrl = "https://api.ipify.org";

  constructor(ownerId, appName, version, secret, debug = true, api = AuthlyX.DefaultBaseUrl) {
    this.ownerId = ownerId || "";
    this.appName = appName || "";
    this.version = version || "";
    this.secret = secret || "";
    this.baseUrl = String(api || AuthlyX.DefaultBaseUrl).trim().replace(/\/+$/, "");
    this.loggingEnabled = debug === undefined ? true : Boolean(debug);

    AuthlyXLogger.AppName = this.appName || "AuthlyX";
    AuthlyXLogger.Enabled = this.loggingEnabled;

    this.sessionId = "";
    this.applicationHash = "";
    this.initialized = false;
    this.cachedPublicIp = "";
    this.cachedPublicIpExpiresAt = 0;

    this.response = {
      success: false,
      message: "",
      raw: "",
      code: "",
      statusCode: 0,
      requestId: "",
      nonce: "",
      signatureKid: ""
    };

    this.userData = {
      username: "",
      email: "",
      licenseKey: "",
      subscription: "",
      subscriptionLevel: "",
      expiryDate: "",
      daysLeft: 0,
      lastLogin: "",
      hwid: "",
      ipAddress: "",
      registeredAt: ""
    };

    this.variableData = {
      varKey: "",
      varValue: "",
      updatedAt: ""
    };

    this.updateData = {
      available: false,
      latestVersion: "",
      downloadUrl: "",
      autoUpdateEnabled: false,
      forceUpdate: false,
      changelog: "",
      showReminder: false,
      reminderMessage: "",
      allowedUntil: ""
    };

    this.chatMessages = {
      channelName: "",
      messages: [],
      count: 0,
      nextCursor: "",
      hasMore: false
    };

    this.applicationHash = this.getCurrentApplicationHash();
    AuthlyXLogger.log(`[SDK] AuthlyX initialized for app '${this.appName}' using '${this.baseUrl}'.`);
  }

  resetResponse() {
    this.response.success = false;
    this.response.message = "";
    this.response.raw = "";
    this.response.code = "";
    this.response.statusCode = 0;
    this.response.requestId = "";
    this.response.nonce = "";
    this.response.signatureKid = "";
  }

  setFailure(code, message, raw = "", statusCode = 0) {
    this.response.success = false;
    this.response.code = code || "";
    this.response.message = message || "";
    this.response.raw = raw || "";
    this.response.statusCode = Number(statusCode || 0);
    return false;
  }

  hasRequiredCredentials() {
    return Boolean(this.ownerId && this.appName && this.version && this.secret);
  }

  canonicalJson(obj) {
    const stable = (value) => {
      if (value === null || value === undefined) return value;
      if (Array.isArray(value)) return value.map(stable);
      if (typeof value !== "object") return value;
      const out = {};
      for (const k of Object.keys(value).sort()) out[k] = stable(value[k]);
      return out;
    };
    return JSON.stringify(stable(obj));
  }

  createSecurityContext() {
    const requestId = crypto.randomUUID();
    const nonce = crypto.randomBytes(16).toString("hex");
    const timestamp = Date.now();
    return { requestId, nonce, timestamp };
  }

  buildUrl(endpoint) {
    const ep = String(endpoint || "").replace(/^\/+/, "");
    return `${this.baseUrl}/${ep}`;
  }

  validateResponseMetadata(headers, requestId, nonce) {
    const respRequestId = headers.get("x-v2-request-id") || "";
    const respNonce = headers.get("x-v2-nonce") || "";
    const kid = headers.get("x-v2-signature-kid") || "";

    if (respRequestId && respRequestId !== requestId) {
      return { ok: false, code: "AUTH_REQUEST_MISMATCH", message: "Response request_id does not match the original request.", kid };
    }
    if (respNonce && respNonce !== nonce) {
      return { ok: false, code: "AUTH_REQUEST_MISMATCH", message: "Response nonce does not match the original request.", kid };
    }
    return { ok: true, kid };
  }

  computeDaysLeft(expiryIso) {
    try {
      if (!expiryIso) return 0;
      const ms = Date.parse(expiryIso);
      if (!Number.isFinite(ms)) return 0;
      const diff = ms - Date.now();
      const days = Math.floor(diff / (24 * 60 * 60 * 1000));
      return days > 0 ? days : 0;
    } catch {
      return 0;
    }
  }

  loadUserData(obj) {
    if (!obj || typeof obj !== "object") return;
    const user = obj.user && typeof obj.user === "object" ? obj.user : null;
    const lic = obj.license && typeof obj.license === "object" ? obj.license : null;
    const dev = obj.device && typeof obj.device === "object" ? obj.device : null;

    if (user) {
      this.userData.username = String(user.username || "");
      this.userData.email = String(user.email || this.userData.email || "");
      this.userData.subscription = String(user.subscription || this.userData.subscription || "");
      this.userData.subscriptionLevel = user.subscription_level === null || user.subscription_level === undefined ? this.userData.subscriptionLevel : String(user.subscription_level);
      this.userData.expiryDate = String(user.expiry_date || this.userData.expiryDate || "");
      this.userData.lastLogin = String(user.last_login || this.userData.lastLogin || "");
      this.userData.registeredAt = String(user.created_at || user.registered_at || this.userData.registeredAt || "");
    }

    if (lic) {
      this.userData.licenseKey = String(lic.license_key || this.userData.licenseKey || "");
      if (!this.userData.subscription) this.userData.subscription = String(lic.subscription || "");
      if (!this.userData.subscriptionLevel && lic.subscription_level !== null && lic.subscription_level !== undefined) {
        this.userData.subscriptionLevel = String(lic.subscription_level);
      }
      if (!this.userData.expiryDate) this.userData.expiryDate = String(lic.expiry_date || "");
    }

    if (dev) {
      if (!this.userData.subscription) this.userData.subscription = String(dev.subscription || "");
      if (!this.userData.subscriptionLevel && dev.subscription_level !== null && dev.subscription_level !== undefined) {
        this.userData.subscriptionLevel = String(dev.subscription_level);
      }
      if (!this.userData.expiryDate) this.userData.expiryDate = String(dev.expiry_date || "");
      if (!this.userData.lastLogin) this.userData.lastLogin = String(dev.last_login || "");
      if (!this.userData.registeredAt) this.userData.registeredAt = String(dev.registered_at || "");
      if (!this.userData.ipAddress) this.userData.ipAddress = String(dev.ip_address || "");
      if (!this.userData.hwid) this.userData.hwid = String(dev.hwid || "");
    }

    if (!this.userData.hwid) this.userData.hwid = this.getSystemIdentifier();
    if (!this.userData.ipAddress) this.userData.ipAddress = this.getPublicIpCached();

    this.userData.daysLeft = this.computeDaysLeft(this.userData.expiryDate);
  }

  loadVariableData(obj) {
    if (!obj || typeof obj !== "object") return;
    const v = obj.variable && typeof obj.variable === "object" ? obj.variable : null;
    if (!v) return;
    this.variableData.varKey = String(v.var_key || "");
    this.variableData.varValue = String(v.var_value || "");
    this.variableData.updatedAt = String(v.updated_at || "");
  }

  loadUpdateData(obj) {
    if (!obj || typeof obj !== "object") return;
    const u = obj.update && typeof obj.update === "object" ? obj.update : null;
    if (!u) {
      if ("auto_update_enabled" in obj || "auto_update_download_url" in obj) {
        this.updateData.available = true;
        this.updateData.latestVersion = String(obj.server_version || obj.version || "");
        this.updateData.autoUpdateEnabled = Boolean(obj.auto_update_enabled);
        this.updateData.downloadUrl = String(obj.auto_update_download_url || "");
        this.updateData.forceUpdate = Boolean(obj.force_update || false);
      }
      return;
    }
    this.updateData.available = Boolean(u.available || false);
    this.updateData.latestVersion = String(u.latest_version || "");
    this.updateData.autoUpdateEnabled = Boolean(u.auto_update_enabled);
    this.updateData.downloadUrl = String(u.download_url || "");
    this.updateData.forceUpdate = Boolean(u.force_update || false);
    this.updateData.changelog = String(u.changelog || "");
    this.updateData.showReminder = Boolean(u.show_reminder || false);
    this.updateData.reminderMessage = String(u.reminder_message || "");
    this.updateData.allowedUntil = u.allowed_until === null || u.allowed_until === undefined ? "" : String(u.allowed_until);
  }

  loadChatData(obj) {
    if (!obj || typeof obj !== "object") return;
    const data = obj.data && typeof obj.data === "object" ? obj.data : null;
    if (!data) return;
    this.chatMessages.channelName = String(data.channel_name || "");
    const msgs = Array.isArray(data.messages) ? data.messages : [];
    this.chatMessages.messages = msgs
      .filter((m) => m && typeof m === "object")
      .map((m) => ({
        id: m.id,
        username: String(m.username || ""),
        message: String(m.message || ""),
        createdAt: String(m.created_at || "")
      }));
    this.chatMessages.count = this.chatMessages.messages.length;
    this.chatMessages.nextCursor = String(data.next_cursor || "");
    this.chatMessages.hasMore = Boolean(data.has_more || false);
  }

  async postJson(endpoint, payload) {
    this.resetResponse();
    if (!payload || typeof payload !== "object") return this.setFailure("INVALID_PAYLOAD", "Payload cannot be null.");

    const ctx = this.createSecurityContext();
    payload.request_id = ctx.requestId;
    payload.nonce = ctx.nonce;
    payload.timestamp = ctx.timestamp;

    const body = this.canonicalJson(payload);
    const url = this.buildUrl(endpoint);

    AuthlyXLogger.log(`[SDK][REQUEST] POST ${url} ${body}`);

    const headers = {
      "content-type": "application/json",
      "user-agent": `AuthlyX-JS-Client/${this.version || "0"}`,
      "x-request-id": ctx.requestId,
      "x-auth-nonce": ctx.nonce,
      "x-auth-timestamp": String(ctx.timestamp)
    };

    try {
      const res = await fetch(url, { method: "POST", headers, body });
      const raw = await res.text();
      AuthlyXLogger.log(`[SDK][RESPONSE] ${res.status} ${raw}`);

      this.response.raw = raw;
      this.response.statusCode = res.status;
      this.response.requestId = ctx.requestId;
      this.response.nonce = ctx.nonce;

      let obj = {};
      try {
        obj = raw ? JSON.parse(raw) : {};
      } catch {
        return this.setFailure("INVALID_JSON", "Invalid JSON response from server.", raw, res.status);
      }

      const headerMap = new Map();
      for (const [k, v] of res.headers.entries()) headerMap.set(k.toLowerCase(), v);
      const meta = this.validateResponseMetadata(headerMap, ctx.requestId, ctx.nonce);
      this.response.signatureKid = meta.kid || "";
      if (!meta.ok) return this.setFailure(meta.code, meta.message, raw, res.status);

      this.response.success = "success" in obj ? Boolean(obj.success) : res.ok;
      this.response.code = String(obj.code || "");
      this.response.message = String(obj.message || res.statusText || "");
      if (!this.response.success && !this.response.code) this.response.code = String(res.status);

      if (obj.session_id) this.sessionId = String(obj.session_id);

      this.loadUserData(obj);
      this.loadVariableData(obj);
      this.loadUpdateData(obj);
      this.loadChatData(obj);

      return this.response.success;
    } catch (e) {
      const msg = e && e.name === "AbortError" ? "Request timed out" : (e && e.message ? e.message : String(e));
      return this.setFailure("NETWORK_ERROR", `Network error: ${msg}`);
    }
  }

  ensureInitialized() {
    if (this.initialized && this.sessionId) return true;
    this.setFailure("NOT_INITIALIZED", "AuthlyX is not initialized. Call Init() first.");
    return false;
  }

  compareSemver(current, latest) {
    const strip = (s) => {
      const t = String(s || "").trim();
      const dash = t.indexOf("-");
      return dash >= 0 ? t.slice(0, dash) : t;
    };
    const parse = (s) => {
      const out = [0, 0, 0];
      const parts = strip(s).split(".");
      for (let i = 0; i < out.length && i < parts.length; i++) {
        const m = String(parts[i]).match(/^\d+/);
        out[i] = m ? Number(m[0]) : 0;
      }
      return out;
    };
    const a = parse(current);
    const b = parse(latest);
    for (let i = 0; i < 3; i++) {
      if (a[i] < b[i]) return -1;
      if (a[i] > b[i]) return 1;
    }
    return 0;
  }

  shouldShowUpdatePrompt(forceShow = false) {
    if (!this.updateData.available) return false;
    if (forceShow) return true;
    if (!this.isClientOutdated()) return false;
    if (!this.hasWhitelistedUpdateMessage()) return false;
    return true;
  }

  openUrl(url) {
    const u = String(url || "").trim();
    if (!u) return;
    try {
      if (process.platform === "win32") childProcess.exec(`cmd /c start "" "${u}"`);
      else if (process.platform === "darwin") childProcess.exec(`open "${u}"`);
      else childProcess.exec(`xdg-open "${u}"`);
    } catch {
      return;
    }
  }

  isClientOutdated() {
    if (!this.updateData.latestVersion) return false;
    return this.compareSemver(this.version, this.updateData.latestVersion) < 0;
  }

  hasWhitelistedUpdateMessage() {
    return Boolean(this.updateData.showReminder || String(this.updateData.allowedUntil || "").trim());
  }

  isAutoUpdateEnabled() {
    return Boolean(this.updateData.autoUpdateEnabled);
  }

  formatDisplayDate(rawDate) {
    const value = String(rawDate || "").trim();
    if (!value) return value;
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return value;
    return parsed.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
  }

  buildWhitelistedUpdateMessage() {
    const allowedUntil = String(this.updateData.allowedUntil || "").trim();
    const base = allowedUntil
      ? `A new version is ready, and you can keep using this build until ${this.formatDisplayDate(allowedUntil)}.`
      : "A new version is ready, and you can still use this build for now.";

    if (!this.isAutoUpdateEnabled()) return base;
    return `${base}\n\nWould you like to download the latest version now?`;
  }

  tryShowWindowsMessageBox(message, yesNo) {
    if (process.platform !== "win32") return null;
    const escape = (value) => String(value || "").replace(/'/g, "''");
    const button = yesNo ? "YesNo" : "OK";
    const script = [
      "Add-Type -AssemblyName PresentationFramework",
      `$result = [System.Windows.MessageBox]::Show('${escape(message)}', 'AuthlyX Update', [System.Windows.MessageBoxButton]::${button}, [System.Windows.MessageBoxImage]::Information)`,
      "Write-Output $result"
    ].join("; ");

    try {
      const out = childProcess.spawnSync("powershell", ["-NoProfile", "-Command", script], { encoding: "utf8" });
      if (out.status === 0) {
        return String(out.stdout || "").trim();
      }
    } catch {
      return null;
    }
    return null;
  }

  async showRequiredUpdateConsole() {
    const message = String(this.response.message || "").trim() || "Please update your app to the latest version.";
    console.log(message);

    const latest = String(this.updateData.latestVersion || "").trim();
    if (latest) console.log(`Latest version: ${latest}`);

    const downloadUrl = String(this.updateData.downloadUrl || "").trim();
    if (!this.isAutoUpdateEnabled() || !downloadUrl) return;

    console.log("1. Download Latest");
    console.log("2. Exit");

    if (!process.stdin || !process.stdin.isTTY) return;

    const readline = require("readline");
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise((resolve) => rl.question("Select an option (1 or 2): ", resolve));
    rl.close();
    if (String(answer || "").trim() === "1") this.openUrl(downloadUrl);
  }

  async promptUpdateIfNeeded(forceShow = false) {
    if (!this.shouldShowUpdatePrompt(forceShow)) return;

    if (forceShow) {
      await this.showRequiredUpdateConsole();
      return;
    }

    const downloadUrl = String(this.updateData.downloadUrl || "").trim();
    const msg = this.buildWhitelistedUpdateMessage();
    const useDownloadPrompt = this.isAutoUpdateEnabled() && !!downloadUrl;
    const messageResult = this.tryShowWindowsMessageBox(msg, useDownloadPrompt);
    if (messageResult) {
      if (useDownloadPrompt && String(messageResult).toLowerCase() === "yes") {
        this.openUrl(downloadUrl);
      }
      return;
    }
    AuthlyXLogger.log(`[UPDATE] ${msg.replace(/\n/g, " | ")}`);

    if (!useDownloadPrompt || !process.stdin || !process.stdin.isTTY) {
      console.log(msg);
      return;
    }

    const readline = require("readline");
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise((resolve) => rl.question("Download the latest version now? (Y/N): ", resolve));
    rl.close();
    const a = String(answer || "").trim().toLowerCase();
    if (a === "y" || a === "yes") this.openUrl(downloadUrl);
  }

  async Init(callback = null) {
    const run = async () => {
      if (!this.hasRequiredCredentials()) {
        this.setFailure("MISSING_CREDENTIALS", "Owner ID, app name, version, and secret are required.");
        return false;
      }
      const payload = {
        owner_id: this.ownerId,
        app_name: this.appName,
        version: this.version,
        secret: this.secret,
        hash: this.getCurrentApplicationHash()
      };
      const ok = await this.postJson("init", payload);
      await this.promptUpdateIfNeeded(String(this.response.code || "").toUpperCase() === "UPDATE_REQUIRED");
      this.initialized = Boolean(ok && this.sessionId);
      return this.initialized;
    };

    if (typeof callback === "function") {
      run().then(() => callback(this.response)).catch(() => callback(this.response));
      return;
    }
    return await run();
  }

  async Login(identifier, password = null, deviceType = null, callback = null) {
    const run = async () => {
      if (deviceType !== null && deviceType !== undefined) return await this.DeviceLogin(deviceType, identifier);
      if (password === null || password === undefined) return await this.LicenseLogin(identifier);
      return await this.UserLogin(identifier, password);
    };

    if (typeof callback === "function") {
      run().then(() => callback(this.response)).catch(() => callback(this.response));
      return;
    }
    return await run();
  }

  async UserLogin(username, password) {
    if (!this.ensureInitialized()) return false;
    const payload = {
      session_id: this.sessionId,
      username: username || "",
      password: password || "",
      sid: this.getSystemIdentifier(),
      ip: this.getPublicIpCached()
    };
    return await this.postJson("login", payload);
  }

  async LicenseLogin(licenseKey) {
    if (!this.ensureInitialized()) return false;
    const payload = {
      session_id: this.sessionId,
      license_key: licenseKey || "",
      sid: this.getSystemIdentifier(),
      ip: this.getPublicIpCached()
    };
    return await this.postJson("licenses", payload);
  }

  async DeviceLogin(deviceType, deviceId) {
    if (!this.ensureInitialized()) return false;
    const payload = {
      session_id: this.sessionId,
      device_type: String(deviceType || "").trim().toLowerCase(),
      device_id: deviceId || "",
      ip: this.getPublicIpCached()
    };
    return await this.postJson("device-auth", payload);
  }

  async Register(username, password, licenseKey, email = "", callback = null) {
    const run = async () => {
      if (!this.ensureInitialized()) return false;
      const payload = {
        session_id: this.sessionId,
        username: username || "",
        password: password || "",
        key: licenseKey || "",
        email: email || "",
        hwid: this.getSystemIdentifier()
      };
      return await this.postJson("register", payload);
    };
    if (typeof callback === "function") {
      run().then(() => callback(this.response)).catch(() => callback(this.response));
      return;
    }
    return await run();
  }

  async ChangePassword(oldPassword, newPassword, callback = null) {
    const run = async () => {
      if (!this.ensureInitialized()) return false;
      const payload = {
        session_id: this.sessionId,
        old_password: oldPassword || "",
        new_password: newPassword || ""
      };
      return await this.postJson("change-password", payload);
    };
    if (typeof callback === "function") {
      run().then(() => callback(this.response)).catch(() => callback(this.response));
      return;
    }
    return await run();
  }

  async ExtendTime(username, licenseKey, callback = null) {
    const run = async () => {
      if (!this.ensureInitialized()) return false;
      const sid = this.getSystemIdentifier();
      const ip = this.getPublicIpCached();
      const payload = {
        session_id: this.sessionId,
        username: username || "",
        license_key: licenseKey || "",
        sid,
        ip
      };
      return await this.postJson("extend", payload);
    };
    if (typeof callback === "function") {
      run().then(() => callback(this.response)).catch(() => callback(this.response));
      return;
    }
    return await run();
  }

  async GetVariable(key, callback = null) {
    const run = async () => {
      if (!this.ensureInitialized()) return "";
      const payload = { session_id: this.sessionId, var_key: key || "" };
      const ok = await this.postJson("variables", payload);
      return ok ? String(this.variableData.varValue || "") : "";
    };
    if (typeof callback === "function") {
      run().then((val) => callback(val, this.response)).catch(() => callback("", this.response));
      return;
    }
    return await run();
  }

  async SetVariable(key, value, callback = null) {
    const run = async () => {
      if (!this.ensureInitialized()) return false;
      const payload = { session_id: this.sessionId, var_key: key || "", var_value: value || "" };
      return await this.postJson("variables/set", payload);
    };
    if (typeof callback === "function") {
      run().then(() => callback(this.response)).catch(() => callback(this.response));
      return;
    }
    return await run();
  }

  async Log(message, callback = null) {
    const run = async () => {
      if (!this.ensureInitialized()) return false;
      const payload = { session_id: this.sessionId, message: message || "" };
      return await this.postJson("logs", payload);
    };
    if (typeof callback === "function") {
      run().then(() => callback(this.response)).catch(() => callback(this.response));
      return;
    }
    return await run();
  }

  async GetChats(channelName, limit = 100, cursor = null, callback = null) {
    const run = async () => {
      if (!this.ensureInitialized()) return false;
      const payload = { session_id: this.sessionId, channel_name: channelName || "", limit: Number(limit || 100) };
      if (cursor) payload.cursor = cursor;
      return await this.postJson("chats/get", payload);
    };
    if (typeof callback === "function") {
      run().then(() => callback(this.response)).catch(() => callback(this.response));
      return;
    }
    return await run();
  }

  async SendChat(message, channelName = null, callback = null) {
    const run = async () => {
      if (!this.ensureInitialized()) return false;
      const payload = { session_id: this.sessionId, message: message || "" };
      if (channelName) payload.channel_name = channelName;
      return await this.postJson("chats/send", payload);
    };
    if (typeof callback === "function") {
      run().then(() => callback(this.response)).catch(() => callback(this.response));
      return;
    }
    return await run();
  }

  async ValidateSession(callback = null) {
    const run = async () => {
      if (!this.initialized || !this.sessionId) {
        this.setFailure("INVALID_SESSION", "No active session. Please login first.");
        return false;
      }
      const payload = { session_id: this.sessionId };
      return await this.postJson("validate-session", payload);
    };
    if (typeof callback === "function") {
      run().then(() => callback(this.response)).catch(() => callback(this.response));
      return;
    }
    return await run();
  }

  IsInitialized() {
    return Boolean(this.initialized);
  }

  GetSessionId() {
    return this.sessionId || "";
  }

  getWindowsSid() {
    try {
      const out = childProcess.execSync('whoami /user /fo csv /nh', { stdio: ["ignore", "pipe", "ignore"] }).toString("utf8").trim();
      if (!out) return "";
      const cols = out.split(",").map((c) => c.trim().replace(/^\"|\"$/g, ""));
      for (const c of cols) if (c.startsWith("S-1-")) return c;
      return cols.length >= 2 && cols[1].startsWith("S-1-") ? cols[1] : "";
    } catch {
      return "";
    }
  }

  getSystemIdentifier() {
    if (process.platform === "win32") {
      const sid = this.getWindowsSid();
      if (sid) return sid;
    }
    try {
      const seed = `${os.userInfo().username}|${os.hostname()}|${process.platform}`;
      return crypto.createHash("sha256").update(seed, "utf8").digest("hex");
    } catch {
      return "UNKNOWN_SID";
    }
  }

  async getPublicIp() {
    try {
      const res = await fetch(AuthlyX.IpLookupUrl, { method: "GET" });
      const ip = (await res.text()).trim();
      return ip || "";
    } catch {
      return "";
    }
  }

  getPublicIpCached() {
    const now = Date.now();
    if (this.cachedPublicIp && now < this.cachedPublicIpExpiresAt) return this.cachedPublicIp;
    return this.cachedPublicIp || "";
  }

  async refreshPublicIpCache() {
    const ip = await this.getPublicIp();
    if (ip) {
      this.cachedPublicIp = ip;
      this.cachedPublicIpExpiresAt = Date.now() + 10 * 60 * 1000;
    }
    return this.cachedPublicIp;
  }

  getHashTargetPath() {
    const arg = process.argv && process.argv.length >= 2 ? process.argv[1] : "";
    if (arg && fs.existsSync(arg)) return path.resolve(arg);
    if (process.execPath && fs.existsSync(process.execPath)) return path.resolve(process.execPath);
    return "";
  }

  getCurrentApplicationHash() {
    try {
      const file = this.getHashTargetPath();
      if (!file) return "UNKNOWN_HASH";
      const buf = fs.readFileSync(file);
      return crypto.createHash("sha256").update(buf).digest("hex");
    } catch {
      return "UNKNOWN_HASH";
    }
  }

  init(callback) { return this.Init(callback); }
  login(identifier, password = null, deviceType = null, callback = null) { return this.Login(identifier, password, deviceType, callback); }
  register(username, password, licenseKey, email = "", callback = null) { return this.Register(username, password, licenseKey, email, callback); }
  changePassword(oldPassword, newPassword, callback = null) { return this.ChangePassword(oldPassword, newPassword, callback); }
  extendTime(username, licenseKey, callback = null) { return this.ExtendTime(username, licenseKey, callback); }
  getVariable(key, callback = null) { return this.GetVariable(key, callback); }
  setVariable(key, value, callback = null) { return this.SetVariable(key, value, callback); }
  validateSession(callback = null) { return this.ValidateSession(callback); }
  getChats(channelName, limit = 100, cursor = null, callback = null) { return this.GetChats(channelName, limit, cursor, callback); }
  sendChat(message, channelName = null, callback = null) { return this.SendChat(message, channelName, callback); }
  isInitialized() { return this.IsInitialized(); }
  getSessionId() { return this.GetSessionId(); }
  getSystemId() { return this.getSystemIdentifier(); }
}

module.exports = { AuthlyX, AuthlyXLogger };
