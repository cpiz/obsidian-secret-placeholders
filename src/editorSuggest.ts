// EditorSuggest with three trigger modes:
//
//   1. `{{` alone               -> list of enabled providers (prefix picker)
//   2. `{{<text>` (no colon)    -> cross-provider fuzzy search across every
//                                  provider's list(), plus any providers
//                                  whose prefix starts with <text>
//   3. `{{<prefix>:<query>`     -> per-provider search
//
// Each provider's list() result is cached for 60s to avoid hitting the
// backend on every keystroke.

import {
  App,
  Editor,
  EditorPosition,
  EditorSuggest,
  EditorSuggestContext,
  EditorSuggestTriggerInfo,
  Notice,
  TFile,
} from "obsidian";

import { t } from "./i18n";
import type SecretPlaceholdersPlugin from "./main";
import { preparePinyinSearch } from "./pinyinSearch";
import type { Provider, ProviderRef } from "./providers/types";

const CACHE_TTL_MS = 60_000;

function candidateLabel(ref: ProviderRef): string {
  return ref.projectLabel ?? ref.suggestionLabel ?? ref.raw.slice(2, -2);
}

function searchProviderRefs(refs: ProviderRef[], query: string): ProviderRef[] {
  if (!query) return refs;
  const filter = query.toLowerCase();
  const matchesPinyin = preparePinyinSearch(query);
  const matches: { ref: ProviderRef; original: boolean }[] = [];
  const originalGroups = new Set<string>();

  for (const ref of refs) {
    const label = candidateLabel(ref);
    const address = ref.projectLabel === undefined ? ref.raw : ref.raw.split("#", 1)[0];
    const original = label.toLowerCase().includes(filter) ||
      address.toLowerCase().includes(filter);
    if (!original && !matchesPinyin?.(label)) continue;
    matches.push({ ref, original });
    if (original && ref.suggestionGroup !== undefined) {
      originalGroups.add(ref.suggestionGroup);
    }
  }

  const first: ProviderRef[] = [];
  const rest: ProviderRef[] = [];
  for (const { ref, original } of matches) {
    // Use the best match in each same-name group to rank it, while
    // keeping the provider's creation order within the group.
    const hasOriginal = original ||
      (ref.suggestionGroup !== undefined && originalGroups.has(ref.suggestionGroup));
    (hasOriginal ? first : rest).push(ref);
  }
  return first.concat(rest);
}

interface ProviderCache {
  fetchedAt: number;
  refs: ProviderRef[];
}

type Suggestion =
  | { kind: "provider"; provider: Provider; label: string }
  | { kind: "ref" | "field"; provider: Provider; ref: ProviderRef; label: string };

export class SecretEditorSuggest extends EditorSuggest<Suggestion> {
  private caches = new Map<string, ProviderCache>();
  private inflight = new Map<string, Promise<ProviderRef[]>>();

  constructor(
    app: App,
    private plugin: SecretPlaceholdersPlugin,
  ) {
    super(app);
  }

  /** Drop the cached per-provider ref lists so the next suggestion query
   *  re-fetches.  Called after a secret is written/edited and from the
   *  "Clear cache" command. */
  clearCache(): void {
    this.caches.clear();
    this.inflight.clear();
  }

  onTrigger(
    cursor: EditorPosition,
    editor: Editor,
    _file: TFile | null,
  ): EditorSuggestTriggerInfo | null {
    const line = editor.getLine(cursor.line);
    const upToCursor = line.slice(0, cursor.ch);
    const open = upToCursor.lastIndexOf("{{");
    if (open === -1) return null;
    const between = upToCursor.slice(open + 2);
    // Bail if the placeholder is already closed.
    if (between.includes("}}")) return null;
    // Bail if the user has typed anything wildly off (newline etc.).
    if (between.includes("\n")) return null;

    return {
      start: { line: cursor.line, ch: open },
      end: cursor,
      query: between, // e.g. "", "bao", "bao:kv/obs", or "github"
    };
  }

  async getSuggestions(ctx: EditorSuggestContext): Promise<Suggestion[]> {
    const query = ctx.query;
    const colon = query.indexOf(":");
    if (colon >= 0) {
      // Mode 3: per-provider search.
      const prefixWithColon = `${query.slice(0, colon)}:`;
      const provider = this.providerByPrefix(prefixWithColon);
      if (!provider) return [];
      const separator = query.indexOf("#", colon + 1);
      if (provider.listFields && separator >= 0) {
        // Parse only the project address. A complete reference needs a
        // non-empty field, even when the user has only typed the separator.
        const raw = `{{${query.slice(0, separator + 1)}_}}`;
        const project = provider.parseRef(raw);
        if (project?.raw !== raw) return [];
        const filter = query.slice(separator + 1).toLowerCase();
        try {
          const fields = await provider.listFields(project);
          return fields
            .filter((ref) => ref.parts.field.toLowerCase().includes(filter))
            .slice(0, 50)
            .map((ref) => ({ kind: "field" as const, provider, ref, label: ref.parts.field }));
        } catch {
          // Missing or ambiguous project names are common while typing.
          return [];
        }
      }
      const refs = await this.getRefs(provider);
      const matches = searchProviderRefs(refs, query.slice(colon + 1));
      return matches.slice(0, 50).map((ref) => ({
        kind: "ref" as const,
        provider,
        ref,
        label: candidateLabel(ref),
      }));
    }

    // Mode 1 + 2: no colon yet.  Show providers that match the typed text
    // first, then cross-provider fuzzy matches against every secret name.
    const providers = this.plugin.registry.all();
    const filter = query.toLowerCase();
    const out: Suggestion[] = [];

    // Provider picks first (they're cheap and definitive).
    for (const p of providers) {
      const prefixWithoutColon = p.placeholderPrefix.replace(/:$/, "");
      if (!filter || prefixWithoutColon.startsWith(filter)) {
        out.push({
          kind: "provider",
          provider: p,
          label: `${p.placeholderPrefix} — ${p.displayName}`,
        });
      }
    }

    // Cross-provider unified fuzzy search.  Only fire when the user has
    // typed something - typing `{{` alone shows the provider list above.
    if (filter) {
      const seen = new Set<string>();
      for (const p of providers) {
        let refs: ProviderRef[];
        try {
          refs = await this.getRefs(p);
        } catch {
          continue;
        }
        for (const ref of refs) {
          const label = candidateLabel(ref);
          if (!label.toLowerCase().includes(filter)) continue;
          // De-duplicate refs that share the same raw text across providers
          // (unlikely but defensive).
          const key = `${p.id}:${ref.raw}`;
          if (seen.has(key)) continue;
          seen.add(key);
          out.push({ kind: "ref", provider: p, ref, label });
          if (out.length >= 50) break;
        }
        if (out.length >= 50) break;
      }
    }

    return out;
  }

  renderSuggestion(s: Suggestion, el: HTMLElement): void {
    el.addClass("sp-suggest");
    el.createDiv({ cls: "sp-suggest__primary", text: s.label });
    el.createDiv({
      cls: "sp-suggest__secondary",
      text:
        s.kind === "provider"
          ? "Provider"
          : s.provider.displayName,
    });
  }

  selectSuggestion(s: Suggestion): void {
    if (!this.context) return;
    const { editor, start, end } = this.context;
    if (s.kind === "provider") {
      // Insert `{{<prefix>:` and let the user keep typing - the next
      // keystroke re-triggers this suggester in mode 3.  Any `}}` that
      // Obsidian's auto-pair-brackets inserted after the cursor is left
      // in place so the user types the rest inside it.
      const inserted = `{{${s.provider.placeholderPrefix}`;
      editor.replaceRange(inserted, start, end);
      // Move the cursor to the end of the inserted text so the suggester
      // wakes up again.
      editor.setCursor({
        line: start.line,
        ch: start.ch + inserted.length,
      });
    } else {
      const trigger = this.onTrigger(editor.getCursor(), editor, null);
      if (!trigger || trigger.start.line !== start.line || trigger.start.ch !== start.ch) return;
      const { end: cursor } = trigger;
      const line = editor.getLine(cursor.line);
      const suffix = line.slice(cursor.ch);
      // Replace the whole search fragment, including any remaining text
      // in its closing braces. Stop before another brace-delimited fragment.
      const closingTail = /^(?:[^{}]*\}\}|\})/.exec(suffix)?.[0] ?? "";
      const replacementEnd = {
        line: cursor.line,
        ch: cursor.ch + closingTail.length,
      };
      const searchText = line.slice(start.ch, replacementEnd.ch);
      const canInsert = () => {
        const current = editor.getCursor();
        return current.line === cursor.line && current.ch === cursor.ch &&
          editor.getLine(cursor.line).slice(start.ch, replacementEnd.ch) === searchText;
      };
      const insert = (ref: ProviderRef) => {
        editor.replaceRange(ref.raw, start, replacementEnd);
        editor.setCursor({ line: start.line, ch: start.ch + ref.raw.length });
      };
      if (s.kind === "field" || !s.provider.listFields) {
        if (canInsert()) insert(s.ref);
      } else {
        void (async () => {
          try {
            const fields = await s.provider.listFields?.(s.ref);
            if (!fields || !canInsert()) return;
            if (fields.length === 0) {
              new Notice(t("modal.secretBrowser.noFields"));
            } else if (fields.length === 1) {
              insert(fields[0]);
            } else {
              // Keep the selected project's exact address, including its ID.
              // Putting the caret after # triggers the inline field search.
              const raw = fields[0].raw;
              const draft = raw.slice(0, raw.indexOf("#") + 1);
              editor.transaction({
                changes: [{ from: start, to: replacementEnd, text: `${draft}}}` }],
                selection: { from: { line: start.line, ch: start.ch + draft.length } },
              });
            }
          } catch (e) {
            if (canInsert()) new Notice(t("notice.readFailed", { msg: (e as Error).message }));
          }
        })();
      }
    }
  }

  private providerByPrefix(prefixWithColon: string): Provider | null {
    for (const p of this.plugin.registry.all()) {
      if (p.placeholderPrefix === prefixWithColon) return p;
    }
    return null;
  }

  private async getRefs(provider: Provider): Promise<ProviderRef[]> {
    const cached = this.caches.get(provider.id);
    if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
      return cached.refs;
    }
    const existing = this.inflight.get(provider.id);
    if (existing) return existing;

    const p = (async () => {
      try {
        const refs = await provider.list();
        // Only cache a non-empty result.  An empty list usually means the
        // provider is logged out or mid-error; caching that would hide
        // real secrets for the full TTL once the user logs in.
        if (refs.length > 0) {
          this.caches.set(provider.id, { fetchedAt: Date.now(), refs });
        }
        return refs;
      } catch {
        return [];
      }
    })();
    this.inflight.set(provider.id, p);
    try {
      return await p;
    } finally {
      this.inflight.delete(provider.id);
    }
  }
}
