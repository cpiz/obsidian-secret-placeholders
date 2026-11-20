// Bitwarden REST API client.  Targets the Vaultwarden / Bitwarden cloud
// REST surface that the official clients use.  Pure `requestUrl` so it
// works on Obsidian desktop and mobile.

import { requestUrl } from "obsidian";

export class BitwardenApiError extends Error {
  status: number;
  body: string;
  constructor(status: number, body: string, message?: string) {
    super(message ?? `Bitwarden ${status}: ${body.slice(0, 200)}`);
    this.status = status;
    this.body = body;
  }
}

function isInvalidGrant(error: BitwardenApiError): boolean {
  if (error.status !== 400) return false;
  try {
    return (JSON.parse(error.body) as { error?: string } | null)?.error === "invalid_grant";
  } catch {
    return false;
  }
}

export interface PreloginResponse {
  /** 0 = PBKDF2-SHA256, 1 = Argon2id. */
  kdf: number;
  kdfIterations: number;
  /** Argon2 only: memory cost in MiB. */
  kdfMemory?: number;
  /** Argon2 only: parallelism (lanes). */
  kdfParallelism?: number;
}

export interface LoginResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
  /** Protected user encryption key in EncString form. */
  key?: string;
  /** Protected RSA private key (not used yet - reserved for org keys). */
  privateKey?: string;
}

export interface DeviceApproval {
  approved: boolean | null;
  encryptedKey?: string;
  encryptedMasterPasswordHash?: string;
}

/** Bitwarden's official server returns JSON with PascalCase keys, while
 *  Vaultwarden returns lowercase/camelCase.  This helper pulls a value out
 *  of an object by trying several common casings so the rest of the code
 *  can use one canonical shape. */
function pick<T>(obj: Record<string, unknown>, ...keys: string[]): T | undefined {
  for (const k of keys) {
    if (k in obj && obj[k] !== undefined) return obj[k] as T;
  }
  return undefined;
}

/** A small subset of the /api/sync response. */
export interface SyncResponse {
  Ciphers: SyncCipher[];
  Folders: SyncFolder[];
  Profile: SyncProfile | null;
}

/** Subset of the sync response's `Profile` we use for organization keys. */
export interface SyncProfile {
  /** RSA private key, EncString-wrapped with the user's symmetric key. */
  PrivateKey: string | null;
  Organizations: SyncProfileOrg[];
}

export interface SyncProfileOrg {
  Id: string;
  /** The org's symmetric key, RSA-encrypted with the user's public key. */
  Key: string;
}

export interface SyncFolder {
  Id: string;
  /** EncString of the folder name. */
  Name: string;
}

export interface SyncCipherField {
  /** EncString of the field name (label). */
  Name: string;
  /** EncString of the field value.  May be null for empty fields. */
  Value: string | null;
  /** Field type: 0=text, 1=hidden (password), 2=boolean, 3=linked. */
  Type?: number;
}

export interface SyncCipherLogin {
  /** EncString. */
  Username: string | null;
  /** EncString. */
  Password: string | null;
  Uris?: Array<{ Uri: string | null; Match: number | null }>;
}

export interface SyncCipher {
  Id: string;
  /** EncString of the item title. */
  Name: string;
  Type: number; // 1=login, 2=secure note, 3=card, 4=identity
  /** Optional per-cipher key (EncString of a 64-byte key, wrapped with the
   *  user or org key).  When present, this cipher's own fields are encrypted
   *  with THIS key, not directly with the user/org key.  Newer Bitwarden
   *  clients assign one per item. */
  Key?: string | null;
  /** Null if at vault root. */
  FolderId: string | null;
  /** Null for a personal cipher; an org id for an organization cipher.
   *  Org ciphers are encrypted with that org's key, not the user key. */
  OrganizationId: string | null;
  Login?: SyncCipherLogin;
  /** Custom fields. */
  Fields?: SyncCipherField[];
  /** EncString of the secure-note text body. */
  Notes?: string | null;
  CreationDate: string | null;
  DeletedDate: string | null;
  /** ISO timestamp. */
  RevisionDate: string;
}

interface ClientOptions {
  baseUrl: string;
  deviceIdentifier: string;
  /** Plugin version, used in the Bitwarden-Client-Version header that
   *  recent Vaultwarden builds require. */
  clientVersion: string;
}

// Conservative bound on the Bitwarden client name some servers (esp.
// Vaultwarden 1.32+) require.  Treat any rejection as fatal so we don't
// leak a partial login attempt to the server.
const CLIENT_NAME = "web";
const DEVICE_TYPE = "8"; // Keep the existing login device type for device approvals.

export class BitwardenClient {
  private accessToken: string | null = null;
  private accessTokenExpiresAt = 0;
  private refreshToken: string | null = null;
  private sessionVersion = 0;
  private refreshInflight: Promise<string> | null = null;

  constructor(
    private opts: ClientOptions,
    private onSessionExpired: () => void = () => {},
    private onRefreshTokenChanged: (token: string) => Promise<void> = async () => {},
  ) {}

  canUseDeviceLogin(): boolean {
    try {
      const url = new URL(this.opts.baseUrl);
      return url.protocol === "https:" && !/(^|\.)bitwarden\.(com|eu)$/i.test(url.hostname);
    } catch {
      return false;
    }
  }

  setTokens(
    accessToken: string,
    expiresInSec: number,
    refreshToken: string | null,
  ): void {
    this.sessionVersion++;
    this.refreshInflight = null;
    this.updateTokens(accessToken, expiresInSec, refreshToken);
  }

  private updateTokens(
    accessToken: string,
    expiresInSec: number,
    refreshToken: string | null,
  ): void {
    this.accessToken = accessToken;
    this.accessTokenExpiresAt = Date.now() + Math.max(0, expiresInSec - 30) * 1000;
    this.refreshToken = refreshToken;
  }

  clearTokens(): void {
    this.sessionVersion++;
    this.refreshInflight = null;
    this.accessToken = null;
    this.refreshToken = null;
    this.accessTokenExpiresAt = 0;
  }

  hasSession(): boolean {
    return this.hasValidAccessToken() || this.refreshToken !== null;
  }

  private hasValidAccessToken(): boolean {
    return (
      this.accessToken !== null && Date.now() < this.accessTokenExpiresAt
    );
  }

  private identityUrl(path: string): string {
    return `${this.opts.baseUrl.replace(/\/+$/, "")}/identity/${path.replace(/^\/+/, "")}`;
  }

  private apiUrl(path: string): string {
    return `${this.opts.baseUrl.replace(/\/+$/, "")}/api/${path.replace(/^\/+/, "")}`;
  }

  private bitwardenHeaders(): Record<string, string> {
    return {
      "Bitwarden-Client-Name": CLIENT_NAME,
      "Bitwarden-Client-Version": this.opts.clientVersion,
    };
  }

  async prelogin(email: string): Promise<PreloginResponse> {
    const res = await requestUrl({
      url: this.identityUrl("accounts/prelogin"),
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...this.bitwardenHeaders(),
      },
      body: JSON.stringify({ email }),
      throw: false,
    });
    if (res.status >= 400) throw new BitwardenApiError(res.status, res.text);
    const raw = (res.json ?? {}) as Record<string, unknown>;
    const kdf = pick<number>(raw, "kdf", "Kdf");
    const kdfIterations = pick<number>(raw, "kdfIterations", "KdfIterations");
    const kdfMemory = pick<number>(raw, "kdfMemory", "KdfMemory");
    const kdfParallelism = pick<number>(
      raw,
      "kdfParallelism",
      "KdfParallelism",
    );
    if (typeof kdf !== "number" || typeof kdfIterations !== "number") {
      throw new BitwardenApiError(
        500,
        JSON.stringify(raw),
        `prelogin response missing kdf/kdfIterations: ${JSON.stringify(raw)}`,
      );
    }
    return { kdf, kdfIterations, kdfMemory, kdfParallelism };
  }

  /** Password grant with a master password hash or approved device request code.
   *
   *  - `newDeviceOtp`: the email-delivered code Bitwarden cloud asks for
   *    on previously-unseen devices.
   *  - `twoFactor`: a TOTP / email / WebAuthn second factor.  We only
   *    issue TOTP (provider="0") from the plugin; other providers are
   *    rejected upstream. */
  async login(
    email: string,
    credential: string,
    deviceName: string,
    extras: {
      authRequestId?: string;
      newDeviceOtp?: string;
      twoFactor?: { token: string; provider: string; remember?: boolean };
    } = {},
  ): Promise<LoginResponse> {
    const body = new URLSearchParams({
      grant_type: "password",
      username: email,
      password: credential,
      scope: "api offline_access",
      client_id: "connector",
      deviceType: DEVICE_TYPE,
      deviceIdentifier: this.opts.deviceIdentifier,
      deviceName,
    });
    if (extras.authRequestId) body.set("authRequest", extras.authRequestId);
    if (extras.newDeviceOtp) body.set("newDeviceOtp", extras.newDeviceOtp);
    if (extras.twoFactor) {
      body.set("twoFactorToken", extras.twoFactor.token);
      body.set("twoFactorProvider", extras.twoFactor.provider);
      body.set(
        "twoFactorRemember",
        extras.twoFactor.remember ? "1" : "0",
      );
    }
    const res = await requestUrl({
      url: this.identityUrl("connect/token"),
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        ...(extras.authRequestId ? { "Device-Type": DEVICE_TYPE } : {}),
        ...this.bitwardenHeaders(),
      },
      body: body.toString(),
      throw: false,
    });
    if (res.status >= 400) throw new BitwardenApiError(res.status, res.text);
    return normalizeLoginResponse(res.json, !extras.authRequestId);
  }

  async createDeviceApproval(email: string, publicKey: string, accessCode: string): Promise<string> {
    if (!this.canUseDeviceLogin()) {
      throw new BitwardenApiError(400, "Device approval requires a self-hosted HTTPS server");
    }
    const res = await requestUrl({
      url: this.apiUrl("auth-requests"),
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Device-Type": DEVICE_TYPE,
        ...this.bitwardenHeaders(),
      },
      body: JSON.stringify({
        email, deviceIdentifier: this.opts.deviceIdentifier, publicKey, accessCode, type: 0,
      }),
      throw: false,
    });
    if (res.status >= 400) throw new BitwardenApiError(res.status, "Unable to request device approval");
    const raw = (res.json ?? {}) as Record<string, unknown>;
    const id = pick<string>(raw, "id", "Id");
    if (typeof id !== "string" || !id) {
      throw new BitwardenApiError(502, "Device approval response has no request ID");
    }
    return id;
  }

  async getDeviceApproval(id: string, accessCode: string): Promise<DeviceApproval> {
    const query = new URLSearchParams({ code: accessCode });
    const res = await requestUrl({
      url: this.apiUrl(`auth-requests/${encodeURIComponent(id)}/response?${query}`),
      method: "GET",
      headers: {
        "Cache-Control": "no-cache",
        "Device-Type": DEVICE_TYPE,
        ...this.bitwardenHeaders(),
      },
      throw: false,
    });
    if (res.status >= 400) throw new BitwardenApiError(res.status, "Unable to check device approval");
    const raw = (res.json ?? {}) as Record<string, unknown>;
    const approved = pick<boolean | null>(raw, "requestApproved", "RequestApproved");
    if (approved !== true && approved !== false && approved !== null) {
      throw new BitwardenApiError(502, "Device approval response has no valid approval state");
    }
    const key = pick<string>(raw, "key", "Key");
    const passwordHash = pick<string>(raw, "masterPasswordHash", "MasterPasswordHash");
    return {
      approved,
      encryptedKey: typeof key === "string" ? key : undefined,
      encryptedMasterPasswordHash: typeof passwordHash === "string" ? passwordHash : undefined,
    };
  }

  /** True if the given error is Bitwarden's "new device verification
   *  required" challenge (HTTP 400 with error=device_error). */
  static isDeviceVerificationError(e: unknown): boolean {
    if (!(e instanceof BitwardenApiError) || e.status !== 400) return false;
    try {
      const j = JSON.parse(e.body) as { error?: string };
      return j.error === "device_error";
    } catch {
      return false;
    }
  }

  /** True if the login response signals 2FA required.  The provider map
   *  is on the response body as `TwoFactorProviders2` (PascalCase, with
   *  the trailing 2) or `twoFactorProviders2` on Vaultwarden. */
  static parseTwoFactorChallenge(
    e: unknown,
  ): { providers: number[] } | null {
    if (!(e instanceof BitwardenApiError) || e.status !== 400) return null;
    try {
      const j = JSON.parse(e.body) as Record<string, unknown>;
      const error = (j.error as string) ?? "";
      const errorDescription = ((j.error_description as string) ?? "").toLowerCase();
      const looksLikeTwoFactor =
        error === "invalid_grant" &&
        errorDescription.includes("two") &&
        errorDescription.includes("factor");
      // The actual provider map may live under several casings.
      const map =
        (j.TwoFactorProviders2 as Record<string, unknown> | undefined) ??
        (j.twoFactorProviders2 as Record<string, unknown> | undefined) ??
        (j.TwoFactorProviders as Record<string, unknown> | undefined) ??
        (j.twoFactorProviders as Record<string, unknown> | undefined);
      if (!looksLikeTwoFactor && !map) return null;
      const providers = map
        ? Object.keys(map).map((k) => Number(k)).filter((n) => !Number.isNaN(n))
        : [];
      return { providers };
    } catch {
      return null;
    }
  }

  async refreshAccessToken(): Promise<string> {
    if (this.refreshInflight) return this.refreshInflight;
    const refreshToken = this.refreshToken;
    if (!refreshToken) {
      if (this.accessToken) this.expireSession();
      throw new BitwardenApiError(401, "not logged in");
    }
    const version = this.sessionVersion;
    const pending = this.exchangeRefreshToken(refreshToken).then(async (tokens) => {
      this.checkSession(version);
      const nextRefreshToken = tokens.refresh_token ?? refreshToken;
      this.updateTokens(tokens.access_token, tokens.expires_in, nextRefreshToken);
      if (nextRefreshToken !== refreshToken) {
        await this.onRefreshTokenChanged(nextRefreshToken);
        this.checkSession(version);
      }
      return tokens.access_token;
    }, (error: unknown) => {
      if (this.sessionVersion === version && error instanceof BitwardenApiError &&
          (error.status === 401 || isInvalidGrant(error))) {
        this.expireSession();
      }
      throw error;
    });
    this.refreshInflight = pending;
    try {
      return await pending;
    } finally {
      if (this.refreshInflight === pending) this.refreshInflight = null;
    }
  }

  private expireSession(): void {
    this.clearTokens();
    this.onSessionExpired();
  }

  private checkSession(version: number): void {
    if (version !== this.sessionVersion) {
      throw new BitwardenApiError(401, "Bitwarden session changed");
    }
  }

  private async exchangeRefreshToken(refreshToken: string): Promise<LoginResponse> {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: "connector",
    });
    const res = await requestUrl({
      url: this.identityUrl("connect/token"),
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        ...this.bitwardenHeaders(),
      },
      body: body.toString(),
      throw: false,
    });
    if (res.status >= 400) throw new BitwardenApiError(res.status, res.text);
    return normalizeLoginResponse(res.json, false);
  }

  private async authedRequest<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const version = this.sessionVersion;
    const accessToken = this.hasValidAccessToken() && this.accessToken
      ? this.accessToken
      : await this.refreshAccessToken();
    this.checkSession(version);
    let res = await this.sendAuthedRequest(accessToken, method, path, body);
    this.checkSession(version);
    if (res.status === 401) {
      // Concurrent requests may already have replaced the rejected token.
      const retryToken = this.accessToken !== accessToken && this.accessToken
        ? this.accessToken
        : await this.refreshAccessToken();
      this.checkSession(version);
      res = await this.sendAuthedRequest(retryToken, method, path, body);
      this.checkSession(version);
      if (res.status === 401 && this.accessToken === retryToken) this.expireSession();
    }
    if (res.status >= 400) throw new BitwardenApiError(res.status, res.text);
    if (res.status === 204 || !res.text) return undefined as unknown as T;
    return res.json as T;
  }

  private sendAuthedRequest(
    accessToken: string,
    method: string,
    path: string,
    body?: unknown,
  ) {
    return requestUrl({
      url: this.apiUrl(path),
      method,
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        Accept: "application/json",
        ...this.bitwardenHeaders(),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      throw: false,
    });
  }

  async sync(): Promise<SyncResponse> {
    const raw = await this.authedRequest<Record<string, unknown>>(
      "GET",
      "sync?excludeDomains=true",
    );
    return normalizeSyncResponse(raw);
  }

  /** Send a fully-formed login-type cipher.  Used for both create and
   *  update so the caller controls every field. */
  createLoginCipher(payload: LoginCipherPayload): Promise<SyncCipher> {
    return this.authedRequest<SyncCipher>(
      "POST",
      "ciphers",
      buildLoginCipherBody(payload),
    );
  }

  async updateLoginCipher(
    cipherId: string,
    payload: LoginCipherPayload,
  ): Promise<void> {
    await this.authedRequest(
      "PUT",
      `ciphers/${cipherId}`,
      buildLoginCipherBody(payload),
    );
  }
}

export interface CustomFieldEnc {
  /** EncString of the field label. */
  nameEnc: string;
  /** EncString of the field value (or null to delete). */
  valueEnc: string | null;
  /** 0 = text, 1 = hidden, 2 = boolean.  Defaults to 1 for new fields. */
  type?: number;
}

export interface LoginCipherPayload {
  nameEnc: string;
  /** The cipher's per-cipher key EncString, echoed back unchanged on update
   *  so the server keeps it (and so the fields, which are encrypted with it,
   *  stay readable).  Null/undefined for ciphers without a per-cipher key. */
  keyEnc?: string | null;
  folderIdOrNull: string | null;
  /** Set for an organization cipher so the server keeps it in that org. */
  organizationIdOrNull?: string | null;
  /** Either field may be null/undefined.  Pre-existing values on update
   *  are NOT preserved by the caller-controlled write API - the caller
   *  must pass through anything they want kept. */
  usernameEnc?: string | null;
  passwordEnc?: string | null;
  notesEnc?: string | null;
  fields?: CustomFieldEnc[];
}

function buildLoginCipherBody(payload: LoginCipherPayload): unknown {
  return {
    Type: 1,
    Name: payload.nameEnc,
    Key: payload.keyEnc ?? null,
    FolderId: payload.folderIdOrNull,
    OrganizationId: payload.organizationIdOrNull ?? null,
    Login: {
      Username: payload.usernameEnc ?? null,
      Password: payload.passwordEnc ?? null,
      Uris: [],
    },
    Notes: payload.notesEnc ?? null,
    Favorite: false,
    Fields: (payload.fields ?? []).map((f) => ({
      Name: f.nameEnc,
      Value: f.valueEnc,
      Type: f.type ?? 1,
    })),
  };
}

function normalizeLoginResponse(raw: unknown, requireKey = true): LoginResponse {
  const r = (raw ?? {}) as Record<string, unknown>;
  const access_token = pick<string>(r, "access_token", "accessToken");
  const refresh_token = pick<string>(r, "refresh_token", "refreshToken");
  const expires_in = pick<number>(r, "expires_in", "expiresIn");
  const token_type = pick<string>(r, "token_type", "tokenType");
  const key = pick<string>(r, "Key", "key");
  const privateKey = pick<string>(r, "PrivateKey", "privateKey");
  if (typeof access_token !== "string" || !access_token ||
      (requireKey && typeof key !== "string")) {
    throw new BitwardenApiError(
      500,
      "Login response is missing an access token or required protected key",
    );
  }
  return {
    access_token,
    refresh_token,
    expires_in: typeof expires_in === "number" ? expires_in : 3600,
    token_type: token_type ?? "Bearer",
    key: typeof key === "string" ? key : undefined,
    privateKey,
  };
}

// --- response normalizers ------------------------------------------------
//
// Bitwarden's official ASP.NET server historically serialized responses in
// PascalCase (`Ciphers`, `Login`, `Password`).  Vaultwarden and newer
// Bitwarden cloud builds increasingly return camelCase (`ciphers`,
// `login`, `password`).  We accept either by reading every field through
// a casing-tolerant picker, so the rest of the provider sees one shape.

function normalizeSyncResponse(raw: unknown): SyncResponse {
  const r = (raw ?? {}) as Record<string, unknown>;
  const ciphersRaw =
    pick<unknown[]>(r, "Ciphers", "ciphers") ?? [];
  const foldersRaw =
    pick<unknown[]>(r, "Folders", "folders") ?? [];
  const profileRaw = pick<unknown>(r, "Profile", "profile");
  return {
    Ciphers: ciphersRaw.map(normalizeCipher),
    Folders: foldersRaw.map(normalizeFolder),
    Profile: profileRaw ? normalizeProfile(profileRaw) : null,
  };
}

function normalizeProfile(raw: unknown): SyncProfile {
  const r = (raw ?? {}) as Record<string, unknown>;
  const orgsRaw = pick<unknown[]>(r, "Organizations", "organizations") ?? [];
  return {
    PrivateKey: pick<string | null>(r, "PrivateKey", "privateKey") ?? null,
    Organizations: orgsRaw.map((o) => {
      const oo = (o ?? {}) as Record<string, unknown>;
      return {
        Id: pick<string>(oo, "Id", "id") ?? "",
        Key: pick<string>(oo, "Key", "key") ?? "",
      };
    }),
  };
}

function normalizeFolder(raw: unknown): SyncFolder {
  const r = (raw ?? {}) as Record<string, unknown>;
  return {
    Id: pick<string>(r, "Id", "id") ?? "",
    Name: pick<string>(r, "Name", "name") ?? "",
  };
}

function normalizeCipher(raw: unknown): SyncCipher {
  const r = (raw ?? {}) as Record<string, unknown>;
  const loginRaw = pick<unknown>(r, "Login", "login");
  const fieldsRaw = pick<unknown[]>(r, "Fields", "fields") ?? [];
  return {
    Id: pick<string>(r, "Id", "id") ?? "",
    Name: pick<string>(r, "Name", "name") ?? "",
    Type: pick<number>(r, "Type", "type") ?? 0,
    Key: pick<string | null>(r, "Key", "key") ?? null,
    FolderId:
      pick<string | null>(r, "FolderId", "folderId") ?? null,
    OrganizationId:
      pick<string | null>(r, "OrganizationId", "organizationId") ?? null,
    Login: loginRaw ? normalizeLogin(loginRaw) : undefined,
    Fields: fieldsRaw.map(normalizeField),
    Notes: pick<string | null>(r, "Notes", "notes") ?? null,
    CreationDate: pick<string | null>(r, "CreationDate", "creationDate") ?? null,
    DeletedDate: pick<string | null>(r, "DeletedDate", "deletedDate") ?? null,
    RevisionDate: pick<string>(r, "RevisionDate", "revisionDate") ?? "",
  };
}

function normalizeLogin(raw: unknown): SyncCipherLogin {
  const r = (raw ?? {}) as Record<string, unknown>;
  const urisRaw = pick<unknown[]>(r, "Uris", "uris") ?? [];
  return {
    Username: pick<string | null>(r, "Username", "username") ?? null,
    Password: pick<string | null>(r, "Password", "password") ?? null,
    Uris: urisRaw.map((u) => {
      const uo = (u ?? {}) as Record<string, unknown>;
      return {
        Uri: pick<string | null>(uo, "Uri", "uri") ?? null,
        Match: pick<number | null>(uo, "Match", "match") ?? null,
      };
    }),
  };
}

function normalizeField(raw: unknown): SyncCipherField {
  const r = (raw ?? {}) as Record<string, unknown>;
  return {
    Name: pick<string>(r, "Name", "name") ?? "",
    Value: pick<string | null>(r, "Value", "value") ?? null,
    Type: pick<number | null>(r, "Type", "type") ?? undefined,
  };
}

/** A stable-ish device identifier so the server doesn't see a new device
 *  every time we log in.  Persisted in plugin data by the provider. */
export function newDeviceIdentifier(): string {
  // RFC 4122 v4-ish, sufficient for the Bitwarden device_identifier slot.
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(
    16,
    20,
  )}-${h.slice(20)}`;
}
