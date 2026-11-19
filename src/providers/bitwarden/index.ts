// Bitwarden / Vaultwarden / Bitwarden cloud provider.
//
// Placeholder syntax: {{vw:[<folder>/]<item>#<field>}} or {{vw://<uuid>#<field>}}
//   - <folder> is optional. If omitted, match by title across folders.
//   - <item> is the cipher (item) title.
//   - <field> is one of:
//       - "password" -> Login.Password or the secure note's custom Password field
//       - "username" -> Login.Username
//       - <custom field label> from cipher.Fields[]
//
// Why both Vaultwarden and Bitwarden cloud here?  Same REST API, different
// hostname.  The Settings tab just takes a baseUrl - point it at your
// Vaultwarden instance, or at https://vault.bitwarden.com for cloud, or
// https://api.bitwarden.eu for the EU region.

import { Notice, Setting } from "obsidian";

import { t } from "../../i18n";
import { renderAuthStatusRow } from "../../authStatusRow";
import {
  decryptBytesWithPassphrase,
  decryptStringWithPassphrase,
  encryptBytesWithPassphrase,
  encryptStringWithPassphrase,
} from "../../crypto/passphraseEncryption";
import {
  DisplayValue,
  NoteContext,
  PluginContext,
  Provider,
  ProviderAuth,
  ProviderAuthStatus,
  ProviderRef,
} from "../types";
import {
  BitwardenClient,
  BitwardenApiError,
  CustomFieldEnc,
  LoginResponse,
  LoginCipherPayload,
  newDeviceIdentifier,
} from "./client";
import {
  SymmetricKey,
  createDeviceLoginKeys,
  decryptBytes,
  decryptString,
  deriveMasterKey,
  encryptString,
  masterPasswordHash,
  stretchMasterKey,
  unpackUserKey,
  unlockOrgKey,
  unlockPrivateKey,
  unlockUserKey,
} from "./crypto";
import {
  BitwardenLoginModal,
  DeviceApprovalModal,
  NewDeviceOtpModal,
  TwoFactorOtpModal,
} from "./loginModal";
import { waitForDeviceApproval } from "./deviceLogin";

// {{vw:[<folder>/]<item>#<field>}}
// We allow the folder portion to be omitted - the regex captures it as an
// empty group when the placeholder has no `/`.  This keeps simple
// references like {{vw:GitHub#password}} readable.
const PLACEHOLDER_RE =
  /\{\{vw:(?:\/\/([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})|(?:([^/#{}]+)\/)?([^/#{}]+))#([^{}]+)\}\}/g;

export interface BitwardenSettings {
  baseUrl: string;
  email: string;
  deviceIdentifier: string;
  /** When true, the user key + refresh token are persisted under a user
   *  passphrase (AES-GCM via passphraseEncryption.ts) so cold-starting
   *  Obsidian doesn't re-prompt for the master password. */
  rememberSession: boolean;
  /** AES-GCM(passphrase)(64-byte user key).  Lets us decrypt ciphers
   *  after restart without re-deriving via PBKDF2/Argon2. */
  encryptedUserKey: string | null;
  /** AES-GCM(passphrase)(refresh_token).  Lets us mint a fresh access
   *  token without re-asking for the master password. */
  encryptedRefreshToken: string | null;
  cacheTtlSec: number;
}

const DEFAULTS: BitwardenSettings = {
  baseUrl: "",
  email: "",
  deviceIdentifier: "",
  rememberSession: false,
  encryptedUserKey: null,
  encryptedRefreshToken: null,
  cacheTtlSec: 300,
};

interface DecryptedCipher {
  id: string;
  name: string;
  type: number;
  createdAt: number;
  folderId: string | null;
  folderName: string | null;
  /** Null for a personal cipher; the org id for an organization cipher.
   *  Determines which key writeKey must encrypt with. */
  orgId: string | null;
  /** The key this cipher's fields are actually encrypted with: its own
   *  per-cipher key when it has one, otherwise the user/org key.  writeKey
   *  must re-encrypt with THIS key, not the user/org key, or the item is
   *  corrupted. */
  itemKey: SymmetricKey;
  /** The raw per-cipher-key EncString (cipher.Key), or null if the cipher
   *  has none.  Must be echoed back on update so the server keeps it. */
  cipherKeyEnc: string | null;
  password: string | null;
  username: string | null;
  fields: Map<string, { value: string; type: number | undefined }>;
  /** Original EncStrings, so writeKey can echo back sibling fields it isn't
   *  touching instead of accidentally clearing them on PUT. */
  raw: {
    nameEnc: string;
    usernameEnc: string | null;
    passwordEnc: string | null;
    notesEnc: string | null;
    /** Custom fields, keyed by lowercased label. */
    fields: Map<
      string,
      { nameEnc: string; valueEnc: string | null; type: number }
    >;
  };
}

export class BitwardenProvider implements Provider {
  readonly id = "vw";
  readonly displayName = "Bitwarden / Vaultwarden";
  readonly placeholderPrefix = "vw:";
  readonly placeholderRegex = PLACEHOLDER_RE;
  // Folder is optional - a root-level item is referenced as {{vw:item#field}}.
  readonly optionalRefParts = ["folder"];

  private settings: BitwardenSettings = { ...DEFAULTS };
  private client: BitwardenClient | null = null;
  /** User encryption key, in memory only.  Cleared on logout. */
  private userKey: SymmetricKey | null = null;
  /** Organization symmetric keys by org id, derived each sync.  Used to
   *  decrypt and write organization-owned ciphers. */
  private orgKeys = new Map<string, SymmetricKey>();
  /** Decrypted cipher cache.  Refreshed on demand. */
  private ciphers: DecryptedCipher[] | null = null;
  private cipherCacheExpires = 0;
  private syncInflight: Promise<DecryptedCipher[]> | null = null;
  private loginAbort: AbortController | null = null;
  private listeners = new Set<() => void>();

  auth: ProviderAuth;

  constructor(private ctx: PluginContext) {
    this.auth = {
      status: async (): Promise<ProviderAuthStatus> => {
        if (!this.client || !this.userKey) return { loggedIn: false };
        return {
          loggedIn: this.client.hasValidAccessToken(),
          identity: this.settings.email || undefined,
        };
      },
      login: async () => {
        if (!this.settings.baseUrl) {
          new Notice(t("provider.bitwarden.serverNotSet"));
          return;
        }
        return this.startLoginFlow();
      },
      logout: async () => {
        this.loginAbort?.abort();
        this.client?.clearTokens();
        this.userKey = null;
        this.orgKeys.clear();
        this.ciphers = null;
        this.cipherCacheExpires = 0;
        this.settings.encryptedUserKey = null;
        this.settings.encryptedRefreshToken = null;
        await this.persist();
        this.ctx.notifyAuthChanged(this.id);
        this.notify();
      },
      onChange: (cb) => {
        this.listeners.add(cb);
        return () => this.listeners.delete(cb);
      },
    };
  }

  private notify(): void {
    for (const cb of this.listeners) {
      try {
        cb();
      } catch {
        /* swallow */
      }
    }
  }

  async init(): Promise<void> {
    const saved = await this.ctx.loadProviderData<BitwardenSettings>(this.id);
    if (saved) this.settings = { ...DEFAULTS, ...saved };
    if (!this.settings.deviceIdentifier) {
      this.settings.deviceIdentifier = newDeviceIdentifier();
      await this.persist();
    }
    if (this.settings.baseUrl) {
      this.client = new BitwardenClient({
        baseUrl: this.settings.baseUrl,
        deviceIdentifier: this.settings.deviceIdentifier,
        clientVersion: this.ctx.pluginVersion ?? "0.0.0",
      });
    }
    // Restore a persisted session if the user opted in.  This prompts for
    // an unlock passphrase; on success we decrypt the user key + refresh
    // token and mint a fresh access token via the refresh_token grant,
    // skipping master-password derivation entirely.
    void this.tryRestoreSession();
  }

  private async tryRestoreSession(): Promise<void> {
    if (
      !this.settings.rememberSession ||
      !this.settings.encryptedUserKey ||
      !this.settings.encryptedRefreshToken ||
      !this.client
    ) {
      return;
    }
    const passphrase = await this.ctx.promptPassphrase(
      t("provider.bitwarden.unlockSession"),
    );
    if (!passphrase) return;
    try {
      const userKeyBytes = await decryptBytesWithPassphrase(
        this.settings.encryptedUserKey,
        passphrase,
      );
      if (userKeyBytes.length !== 64) {
        throw new Error(
          `restored user key has wrong length (${userKeyBytes.length})`,
        );
      }
      const refreshToken = await decryptStringWithPassphrase(
        this.settings.encryptedRefreshToken,
        passphrase,
      );
      // Stash the refresh token on the client so refresh() can use it.
      this.client.setTokens("", 0, refreshToken);
      const refreshed = await this.client.refresh();
      this.client.setTokens(
        refreshed.access_token,
        refreshed.expires_in,
        refreshed.refresh_token ?? refreshToken,
      );
      this.userKey = {
        encKey: userKeyBytes.slice(0, 32),
        macKey: userKeyBytes.slice(32, 64),
      };
      this.ctx.notifyAuthChanged(this.id);
      this.notify();
      new Notice(t("provider.bitwarden.sessionRestored"));
    } catch (e) {
      // Wrong passphrase or expired refresh token - leave the encrypted
      // blobs in place and fall back to the regular master-password flow.
      new Notice(
        t("provider.bitwarden.restoreFailed", { msg: (e as Error).message }),
      );
    }
  }

  private async persistSession(
    userKey: { encKey: Uint8Array; macKey: Uint8Array },
    refreshToken: string | null,
    signal: AbortSignal,
  ): Promise<void> {
    if (!refreshToken) {
      // Without a refresh token we can't restore later, so don't bother
      // persisting the user key either.
      this.settings.encryptedUserKey = null;
      this.settings.encryptedRefreshToken = null;
      await this.persist();
      return;
    }
    const passphrase = await this.ctx.promptPassphrase(
      t("provider.bitwarden.setUnlockPassphrase"),
    );
    signal.throwIfAborted();
    if (!passphrase) {
      // User cancelled - turn rememberSession back off and clear any old
      // blobs so the next cold-start doesn't show a misleading prompt.
      this.settings.rememberSession = false;
      this.settings.encryptedUserKey = null;
      this.settings.encryptedRefreshToken = null;
      await this.persist();
      return;
    }
    const packed = new Uint8Array(64);
    packed.set(userKey.encKey, 0);
    packed.set(userKey.macKey, 32);
    const encryptedUserKey = await encryptBytesWithPassphrase(packed, passphrase);
    packed.fill(0);
    const encryptedRefreshToken = await encryptStringWithPassphrase(
      refreshToken,
      passphrase,
    );
    signal.throwIfAborted();
    this.settings.encryptedUserKey = encryptedUserKey;
    this.settings.encryptedRefreshToken = encryptedRefreshToken;
    await this.persist();
  }

  private async persist(): Promise<void> {
    await this.ctx.saveProviderData(this.id, this.settings);
  }

  private promptDeviceOtp(email: string): Promise<string | null> {
    return new Promise<string | null>((resolve) => {
      window.setTimeout(() => {
        new NewDeviceOtpModal(this.ctx.app, email, (code) =>
          resolve(code),
        ).open();
      }, 50);
    });
  }

  private promptTwoFactorOtp(): Promise<string | null> {
    return new Promise<string | null>((resolve) => {
      window.setTimeout(() => {
        new TwoFactorOtpModal(this.ctx.app, (code) => resolve(code)).open();
      }, 50);
    });
  }

  private async startLoginFlow(): Promise<void> {
    const client = this.client;
    if (!client || this.loginAbort) return;
    const controller = new AbortController();
    const { signal } = controller;
    this.loginAbort = controller;
    const serverUrl = this.settings.baseUrl;
    const deviceLoginAvailable = client.canUseDeviceLogin();

    return new Promise<void>((resolve) => {
      const modal = new BitwardenLoginModal(
        this.ctx.app,
        this.settings.email,
        serverUrl,
        deviceLoginAvailable,
        async (creds) => {
          signal.removeEventListener("abort", close);
          try {
            if (!creds) return;
            signal.throwIfAborted();
            if (this.client !== client) throw new Error(t("provider.bitwarden.deviceLoginRequestFailed"));
            this.settings.email = creds.email;
            await this.persist();
            if (creds.method === "device") {
              await this.performDeviceLogin(client, creds.email.toLowerCase(), controller);
            } else {
              await this.performLogin(client, creds.email, creds.masterPassword, signal);
            }
            new Notice(t("provider.bitwarden.loggedIn"));
          } catch (e) {
            if (!signal.aborted) {
              new Notice(t("provider.bitwarden.loginFailed", { msg: (e as Error).message }));
            }
          } finally {
            this.loginAbort = null;
            if (creds && !signal.aborted) {
              this.ctx.notifyAuthChanged(this.id);
              this.notify();
            }
            resolve();
          }
        },
      );
      const close = () => modal.close();
      signal.addEventListener("abort", close, { once: true });
      modal.open();
    });
  }

  private async performLogin(
    client: BitwardenClient,
    email: string,
    masterPassword: string,
    signal: AbortSignal,
  ): Promise<void> {
    const pre = await client.prelogin(email);
    const masterKey = await deriveMasterKey(masterPassword, email, {
      kdf: pre.kdf,
      iterations: pre.kdfIterations,
      memory: pre.kdfMemory,
      parallelism: pre.kdfParallelism,
    });
    const passwordHash = await masterPasswordHash(masterKey, masterPassword);
    const stretched = await stretchMasterKey(masterKey);
    const login = await this.exchangeLoginToken(client, email, passwordHash, signal);
    if (!login.key) throw new Error("Missing protected user key");
    await this.completeLogin(client, login, await unlockUserKey(stretched, login.key), signal);
  }

  private async performDeviceLogin(
    client: BitwardenClient,
    email: string,
    controller: AbortController,
  ): Promise<void> {
    const { signal } = controller;
    signal.throwIfAborted();
    const keys = await createDeviceLoginKeys(email);
    signal.throwIfAborted();
    const modal = new DeviceApprovalModal(this.ctx.app, keys.fingerprint, () => controller.abort());
    modal.open();
    const approval = await waitForDeviceApproval(
      client, email, keys.publicKey, keys.accessCode, signal, () => modal.waiting(),
    ).finally(() => modal.finish());
    signal.throwIfAborted();

    let rawKey: Uint8Array;
    try {
      rawKey = await keys.decryptApprovalKey(approval.encryptedKey);
    } catch {
      throw new Error(t("provider.bitwarden.deviceLoginKeyFailed"));
    }
    try {
      if (rawKey.length !== (approval.legacy ? 32 : 64)) {
        throw new Error(t("provider.bitwarden.deviceLoginKeyFailed"));
      }
      const login = await this.exchangeLoginToken(
        client, email, keys.accessCode, signal, approval.requestId,
      );
      let userKey: SymmetricKey;
      try {
        // Older approving clients send the master key rather than the user key.
        if (approval.legacy) {
          if (!login.key) throw new Error("Missing protected user key");
          userKey = await unlockUserKey(await stretchMasterKey(rawKey), login.key);
        } else {
          userKey = unpackUserKey(rawKey);
        }
      } catch {
        throw new Error(t("provider.bitwarden.deviceLoginKeyFailed"));
      }
      await this.completeLogin(client, login, userKey, signal);
    } finally {
      rawKey.fill(0);
    }
  }

  private async exchangeLoginToken(
    client: BitwardenClient,
    email: string,
    credential: string,
    signal: AbortSignal,
    authRequestId?: string,
  ): Promise<LoginResponse> {
    const deviceName = "Obsidian Secret Placeholders";
    let newDeviceOtp: string | undefined;
    let twoFactor: { token: string; provider: string } | undefined;

    // Up to three attempts: first plain, then with each missing piece
    // (device OTP, 2FA TOTP) on demand.  Both challenges can appear in
    // any order depending on the server.
    for (let i = 0; i < 3; i++) {
      signal.throwIfAborted();
      try {
        const result = await client.login(email, credential, deviceName, {
          authRequestId, newDeviceOtp, twoFactor,
        });
        signal.throwIfAborted();
        return result;
      } catch (e) {
        signal.throwIfAborted();
        if (BitwardenClient.isDeviceVerificationError(e) && !newDeviceOtp) {
          const otp = await this.promptDeviceOtp(email);
          if (!otp) throw new Error(t("provider.bitwarden.deviceVerifCancelled"));
          newDeviceOtp = otp;
          continue;
        }
        const twoFa = BitwardenClient.parseTwoFactorChallenge(e);
        if (twoFa && !twoFactor) {
          if (!twoFa.providers.includes(0)) {
            throw new Error(
              t("provider.bitwarden.totpNotEnabled", {
                providers: twoFa.providers.join(", "),
              }),
            );
          }
          const code = await this.promptTwoFactorOtp();
          if (!code) throw new Error(t("provider.bitwarden.twoFactorCancelled"));
          twoFactor = { token: code, provider: "0" };
          continue;
        }
        if (authRequestId) throw new Error(t("provider.bitwarden.deviceLoginTokenFailed"));
        throw e;
      }
    }
    throw new Error(t("provider.bitwarden.loginRetriesExhausted"));
  }

  private async completeLogin(
    client: BitwardenClient,
    loginRes: LoginResponse,
    userKey: SymmetricKey,
    signal: AbortSignal,
  ): Promise<void> {
    signal.throwIfAborted();
    if (this.client !== client) throw new Error(t("provider.bitwarden.serverUrlNotSet"));
    client.setTokens(
      loginRes.access_token,
      loginRes.expires_in,
      loginRes.refresh_token ?? null,
    );
    this.userKey = userKey;
    // Invalidate any cached ciphers from a previous session.
    this.ciphers = null;
    this.cipherCacheExpires = 0;

    if (this.settings.rememberSession) {
      await this.persistSession(userKey, loginRes.refresh_token ?? null, signal);
    }
  }

  dispose(): void {
    this.loginAbort?.abort();
  }

  parseRef(raw: string): ProviderRef | null {
    const m = new RegExp(PLACEHOLDER_RE.source).exec(raw);
    if (!m) return null;
    return {
      provider: this.id,
      raw: m[0],
      parts: m[1]
        ? { id: m[1], field: m[4] }
        : { folder: m[2] ?? "", item: m[3], field: m[4] },
    };
  }

  formatRef(parts: Record<string, string>): string {
    const { id, folder, item, field } = parts;
    if (id) return `{{vw://${id}#${field}}}`;
    if (folder) return `{{vw:${folder}/${item}#${field}}}`;
    return `{{vw:${item}#${field}}}`;
  }

  async readKey(ref: ProviderRef): Promise<string> {
    return (await this.readForDisplay(ref)).value;
  }

  async readForDisplay(ref: ProviderRef): Promise<DisplayValue> {
    const ciphers = await this.getCiphers();
    const match = findCipher(ciphers, ref.parts);
    if (!match) {
      const item = ref.parts.id ?? ref.parts.item;
      throw new BitwardenApiError(
        404,
        `item '${item}' not found`,
        `item '${item}' not found in Bitwarden`,
      );
    }
    const field = (ref.parts.field ?? "").toLowerCase();
    if (field === "password" && match.type === 1) {
      if (match.password === null) {
        throw new BitwardenApiError(404, "no password on item");
      }
      return { value: match.password, alwaysVisible: false };
    }
    if (field === "username") {
      if (match.username === null) {
        throw new BitwardenApiError(404, "no username on item");
      }
      return { value: match.username, alwaysVisible: match.type === 1 };
    }
    const v = match.fields.get(field);
    if (v === undefined) {
      throw new BitwardenApiError(404, `field '${ref.parts.field}' not found`);
    }
    return {
      value: v.value,
      alwaysVisible: field !== "password" && (v.type === 0 || v.type === 2),
    };
  }

  async writeKey(ref: ProviderRef, value: string): Promise<void> {
    if (!this.client || !this.userKey) {
      throw new BitwardenApiError(401, "not logged in to Bitwarden");
    }
    const fieldLabel = ref.parts.field ?? "";
    const field = fieldLabel.toLowerCase();
    const ciphers = await this.getCiphers();
    const existing = findCipher(ciphers, ref.parts);
    if (ref.parts.id && !existing) {
      throw new BitwardenApiError(404, `item '${ref.parts.id}' not found`);
    }
    if (existing?.type === 2 && field === "password") {
      const message = t("provider.bitwarden.editSecureNotePasswordInVault");
      throw new BitwardenApiError(400, message, message);
    }
    if (ref.parts.id && existing?.type !== 1) {
      throw new BitwardenApiError(400, "only login items can be updated by ID");
    }

    if (existing) {
      // Patch: start from the existing EncStrings so sibling fields don't
      // get blown away.  Overwrite just the target slot.  Re-encrypt with
      // the SAME key the item already uses - its per-cipher key if it has
      // one, otherwise the org key (org cipher) or the user key (personal).
      // Using the wrong key here corrupts the item.
      const cipherKey = existing.itemKey;
      const payload: LoginCipherPayload = {
        nameEnc: existing.raw.nameEnc,
        keyEnc: existing.cipherKeyEnc,
        folderIdOrNull: existing.folderId,
        organizationIdOrNull: existing.orgId,
        usernameEnc: existing.raw.usernameEnc,
        passwordEnc: existing.raw.passwordEnc,
        notesEnc: existing.raw.notesEnc,
        fields: [...existing.raw.fields.values()].map((f) => ({
          nameEnc: f.nameEnc,
          valueEnc: f.valueEnc,
          type: f.type,
        })),
      };
      await this.applyFieldWrite(
        payload,
        cipherKey,
        field,
        fieldLabel,
        value,
        existing,
      );
      await this.client.updateLoginCipher(existing.id, payload);
    } else {
      // Brand-new cipher - always created in the personal vault.
      const nameEnc = await encryptString(this.userKey, ref.parts.item);
      const payload: LoginCipherPayload = {
        nameEnc,
        folderIdOrNull: await this.resolveFolderId(ref.parts.folder),
        organizationIdOrNull: null,
        usernameEnc: null,
        passwordEnc: null,
        notesEnc: null,
        fields: [],
      };
      await this.applyFieldWrite(
        payload,
        this.userKey,
        field,
        fieldLabel,
        value,
        null,
      );
      await this.client.createLoginCipher(payload);
    }
    this.ciphers = null;
    this.cipherCacheExpires = 0;
  }

  private async applyFieldWrite(
    payload: LoginCipherPayload,
    key: SymmetricKey,
    fieldKey: string,
    fieldLabel: string,
    value: string,
    existing: DecryptedCipher | null,
  ): Promise<void> {
    const enc = (s: string) => encryptString(key, s);
    switch (fieldKey) {
      case "password":
        payload.passwordEnc = await enc(value);
        return;
      case "username":
        payload.usernameEnc = await enc(value);
        return;
      case "notes":
        payload.notesEnc = await enc(value);
        return;
      default: {
        // Custom field: find-or-create by lowercased label.
        const fields = payload.fields ?? [];
        const existingRaw = existing?.raw.fields.get(fieldKey);
        const nameEnc = existingRaw
          ? existingRaw.nameEnc
          : await enc(fieldLabel);
        const newEntry: CustomFieldEnc = {
          nameEnc,
          valueEnc: await enc(value),
          type: existingRaw?.type ?? 1,
        };
        const replacedFields: CustomFieldEnc[] = [];
        let replaced = false;
        for (const f of fields) {
          if (existingRaw && f.nameEnc === existingRaw.nameEnc) {
            replacedFields.push(newEntry);
            replaced = true;
          } else {
            replacedFields.push(f);
          }
        }
        if (!replaced) replacedFields.push(newEntry);
        payload.fields = replacedFields;
        return;
      }
    }
  }

  async list(): Promise<ProviderRef[]> {
    if (!this.client || !this.userKey) return [];
    let ciphers: DecryptedCipher[];
    try {
      ciphers = await this.getCiphers();
    } catch {
      return [];
    }
    const byName = new Map<string, DecryptedCipher[]>();
    for (const cipher of ciphers) {
      const name = cipher.name.toLowerCase();
      const group = byName.get(name) ?? [];
      group.push(cipher);
      byName.set(name, group);
    }

    const refs: ProviderRef[] = [];
    for (const [name, group] of byName) {
      group.sort((a, b) => a.createdAt - b.createdAt || a.id.localeCompare(b.id));
      for (const cipher of group) {
        const namedParts = {
          folder: cipher.folderName ?? "",
          item: cipher.name,
          field: "password",
        };
        const conflicts = group.some((other) => other !== cipher && (
          !other.folderName || matchesCipherName(other, namedParts)
        ));
        const parts = conflicts ? { id: cipher.id, field: namedParts.field } : namedParts;
        const ref: ProviderRef = { provider: this.id, raw: this.formatRef(parts), parts };
        if (group.length > 1) {
          const date = Number.isFinite(cipher.createdAt)
            ? new Date(cipher.createdAt).toLocaleString()
            : "";
          ref.suggestionLabel = [
            this.formatRef(namedParts).slice(2, -2),
            date,
            cipher.id.slice(-8),
          ].filter(Boolean).join(" · ");
          ref.suggestionGroup = name;
        }
        refs.push(ref);
      }
    }
    return refs;
  }

  clearCache(): void {
    this.ciphers = null;
    this.cipherCacheExpires = 0;
  }

  suggestRefDefaults(ctx: NoteContext): Record<string, string> {
    return {
      folder: "",
      item: ctx.basename ?? "untitled",
      field: "password",
    };
  }

  renderSettings(containerEl: HTMLElement): void {
    new Setting(containerEl)
      .setName(t("provider.bitwarden.serverHeading"))
      .setHeading();

    renderAuthStatusRow(containerEl, this);

    new Setting(containerEl)
      .setName(t("provider.bitwarden.serverUrl.name"))
      .setDesc(t("provider.bitwarden.serverUrl.desc"))
      .addText((txt) =>
        txt
          .setPlaceholder("https://vw.example.com")
          .setValue(this.settings.baseUrl)
          .onChange(async (v) => {
            this.loginAbort?.abort();
            this.settings.baseUrl = v.replace(/\/+$/, "");
            if (this.settings.baseUrl) {
              this.client = new BitwardenClient({
                baseUrl: this.settings.baseUrl,
                deviceIdentifier: this.settings.deviceIdentifier,
                clientVersion: this.ctx.pluginVersion ?? "0.0.0",
              });
            }
            await this.persist();
          }),
      );

    new Setting(containerEl)
      .setName(t("provider.bitwarden.email.name"))
      .addText((txt) =>
        txt.setValue(this.settings.email).onChange(async (v) => {
          this.settings.email = v.trim();
          await this.persist();
        }),
      );

    new Setting(containerEl)
      .setName(t("provider.bitwarden.cacheTtl.name"))
      .setDesc(t("provider.bitwarden.cacheTtl.desc"))
      .addText((txt) =>
        txt.setValue(String(this.settings.cacheTtlSec)).onChange(async (v) => {
          const n = Number(v);
          if (!Number.isFinite(n) || n < 0) return;
          this.settings.cacheTtlSec = n;
          await this.persist();
        }),
      );

    new Setting(containerEl)
      .setName(t("provider.bitwarden.rememberSession.name"))
      .setDesc(t("provider.bitwarden.rememberSession.desc"))
      .addToggle((tog) =>
        tog
          .setValue(this.settings.rememberSession)
          .onChange(async (v) => {
            this.settings.rememberSession = v;
            if (!v) {
              this.settings.encryptedUserKey = null;
              this.settings.encryptedRefreshToken = null;
            }
            await this.persist();
          }),
      );
  }

  // --- internals ---------------------------------------------------------

  private async getCiphers(): Promise<DecryptedCipher[]> {
    const userKey = this.userKey;
    if (!userKey) throw new BitwardenApiError(401, "not logged in");
    const now = Date.now();
    if (this.ciphers && now < this.cipherCacheExpires) return this.ciphers;
    if (this.syncInflight) return this.syncInflight;
    this.syncInflight = this.syncAndDecrypt().then((ciphers) => {
      if (this.userKey !== userKey) {
        throw new BitwardenApiError(401, "Bitwarden session changed during sync");
      }
      return ciphers;
    });
    try {
      const c = await this.syncInflight;
      this.ciphers = c;
      this.cipherCacheExpires =
        Date.now() + this.settings.cacheTtlSec * 1000;
      return c;
    } finally {
      this.syncInflight = null;
    }
  }

  private async syncAndDecrypt(): Promise<DecryptedCipher[]> {
    if (!this.client || !this.userKey) {
      throw new BitwardenApiError(401, "not logged in");
    }
    const res = await this.client.sync();

    // Derive organization keys: decrypt the user's RSA private key with the
    // user key, then RSA-decrypt each org's symmetric key.  Org ciphers are
    // encrypted with these, not the user key.  Any failure here just means
    // org ciphers stay invisible - personal ciphers are unaffected.
    this.orgKeys = new Map<string, SymmetricKey>();
    const orgs = res.Profile?.Organizations ?? [];
    if (res.Profile?.PrivateKey && orgs.length > 0) {
      try {
        const rsaKey = await unlockPrivateKey(
          this.userKey,
          res.Profile.PrivateKey,
        );
        for (const org of orgs) {
          if (!org.Id || !org.Key) continue;
          try {
            this.orgKeys.set(org.Id, await unlockOrgKey(rsaKey, org.Key));
          } catch {
            /* skip an org whose key we can't unwrap */
          }
        }
      } catch {
        /* no private key / import failed - personal ciphers only */
      }
    }

    const folderById = new Map<string, string>();
    for (const f of res.Folders ?? []) {
      const name = await safeDecrypt(this.userKey, f.Name);
      if (name !== null) folderById.set(f.Id, name);
    }

    const out: DecryptedCipher[] = [];
    for (const c of res.Ciphers ?? []) {
      if (c.DeletedDate) continue;
      // Only login-type ciphers carry .Login (password + username). Custom
      // fields exist on every cipher type, so we still surface them.
      if (c.Type !== 1 && c.Type !== 2) continue;
      // Pick the key: org ciphers use their org key, personal use userKey.
      // An org cipher whose key we couldn't unwrap is skipped.
      const key = c.OrganizationId
        ? this.orgKeys.get(c.OrganizationId)
        : this.userKey;
      if (!key) continue;
      // Newer ciphers carry their own key (cipher.Key): a 64-byte symmetric
      // key, EncString-wrapped with the user/org key.  When present, the
      // cipher's fields are encrypted with THIS key, not the user/org key
      // directly.  Unwrap it and use it for every field below; fall back to
      // the base key for older ciphers that have no per-cipher key.
      let itemKey: SymmetricKey = key;
      if (c.Key) {
        try {
          const raw = await decryptBytes(key, c.Key);
          if (raw.length !== 64) continue;
          itemKey = { encKey: raw.slice(0, 32), macKey: raw.slice(32, 64) };
        } catch {
          // Can't unwrap this cipher's key - leave it out rather than
          // surfacing an undecryptable item.
          continue;
        }
      }
      const name = await safeDecrypt(itemKey, c.Name);
      if (name === null) continue;
      const password = c.Login?.Password
        ? await safeDecrypt(itemKey, c.Login.Password)
        : null;
      const username = c.Login?.Username
        ? await safeDecrypt(itemKey, c.Login.Username)
        : null;
      const fields: DecryptedCipher["fields"] = new Map();
      const rawFields = new Map<
        string,
        { nameEnc: string; valueEnc: string | null; type: number }
      >();
      for (const f of c.Fields ?? []) {
        if (!f.Name) continue;
        const fname = await safeDecrypt(itemKey, f.Name);
        if (fname === null) continue;
        const fval = f.Value ? await safeDecrypt(itemKey, f.Value) : "";
        fields.set(fname.toLowerCase(), { value: fval ?? "", type: f.Type });
        rawFields.set(fname.toLowerCase(), {
          nameEnc: f.Name,
          valueEnc: f.Value ?? null,
          // Keep the existing write payload default for fields without a type.
          type: f.Type ?? 0,
        });
      }
      const createdAt = Date.parse(c.CreationDate ?? "");
      out.push({
        id: c.Id,
        name,
        type: c.Type,
        createdAt: Number.isFinite(createdAt) ? createdAt : Number.POSITIVE_INFINITY,
        folderId: c.FolderId,
        folderName: c.FolderId ? folderById.get(c.FolderId) ?? null : null,
        orgId: c.OrganizationId,
        itemKey,
        cipherKeyEnc: c.Key ?? null,
        password,
        username,
        fields,
        raw: {
          nameEnc: c.Name,
          usernameEnc: c.Login?.Username ?? null,
          passwordEnc: c.Login?.Password ?? null,
          notesEnc: c.Notes ?? null,
          fields: rawFields,
        },
      });
    }
    return out;
  }

  private async resolveFolderId(folderName: string): Promise<string | null> {
    if (!folderName) return null;
    if (!this.client) return null;
    const res = await this.client.sync();
    for (const f of res.Folders ?? []) {
      const name = await safeDecrypt(this.userKey!, f.Name);
      if (name === folderName) return f.Id;
    }
    // Auto-creating folders is out of scope for v0.4 - if the folder
    // doesn't exist, we place the cipher at the vault root and the user
    // can move it in any regular Bitwarden client.
    return null;
  }
}

function matchesCipherName(cipher: DecryptedCipher, parts: Record<string, string>): boolean {
  return cipher.name.toLowerCase() === parts.item.toLowerCase() && (
    !parts.folder || cipher.folderName?.toLowerCase() === parts.folder.toLowerCase()
  );
}

function findCipher(
  ciphers: DecryptedCipher[],
  parts: Record<string, string>,
): DecryptedCipher | undefined {
  if (parts.id) {
    const id = parts.id.toLowerCase();
    return ciphers.find((cipher) => cipher.id.toLowerCase() === id);
  }
  const matches = ciphers.filter((cipher) => matchesCipherName(cipher, parts));
  if (matches.length > 1) {
    const message = t("provider.bitwarden.ambiguousItem", { item: parts.item });
    throw new BitwardenApiError(409, message, message);
  }
  return matches[0];
}

async function safeDecrypt(
  key: SymmetricKey,
  encString: string,
): Promise<string | null> {
  try {
    return await decryptString(key, encString);
  } catch {
    return null;
  }
}
