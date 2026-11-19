// Fuzzy-search across known secrets from every enabled provider.  Used by
// the "Browse and insert" / "Browse and copy" commands so the user doesn't
// have to remember exact paths.

import { App, FuzzySuggestModal, type FuzzyMatch } from "obsidian";
import { t } from "../i18n";
import { preparePinyinSearch } from "../pinyinSearch";
import type SecretPlaceholdersPlugin from "../main";
import type { Provider, ProviderRef } from "../providers/types";

interface Entry {
  provider: Provider;
  ref: ProviderRef;
  order: number;
}

export class SecretBrowserModal extends FuzzySuggestModal<Entry> {
  private entries: Entry[] = [];

  constructor(
    app: App,
    private plugin: SecretPlaceholdersPlugin,
    private onChoose: (entry: Entry) => void | Promise<void>,
  ) {
    super(app);
    this.setPlaceholder(t("modal.secretBrowser.searchPlaceholder"));
  }

  onOpen(): void {
    void super.onOpen();
    void this.load();
  }

  private async load(): Promise<void> {
    const out: Entry[] = [];
    for (const provider of this.plugin.registry.all()) {
      try {
        const refs = await provider.list();
        for (const ref of refs) out.push({ provider, ref, order: out.length });
      } catch {
        /* skip providers that fail to list */
      }
    }
    this.entries = out;
    // FuzzySuggestModal doesn't auto-refresh on data change, so simulate
    // an input event to force a re-query.
    this.inputEl.dispatchEvent(new Event("input"));
  }

  getItems(): Entry[] {
    return this.entries;
  }

  getSuggestions(query: string): FuzzyMatch<Entry>[] {
    const matches = super.getSuggestions(query);
    const matchesPinyin = preparePinyinSearch(query);
    if (matchesPinyin) {
      const matchedItems = new Set(matches.map(({ item }) => item));
      for (const item of this.entries) {
        if (matchedItems.has(item)) continue;
        const label = item.ref.suggestionLabel ?? item.ref.raw.slice(2, -2);
        if (matchesPinyin(label)) {
          matches.push({ item, match: { score: 0, matches: [] } });
        }
      }
    }

    const groups = new Map<string, FuzzyMatch<Entry>[]>();
    for (const match of matches) {
      const { provider, ref } = match.item;
      if (ref.suggestionGroup === undefined) continue;
      const key = `${provider.id}:${ref.suggestionGroup}`;
      const group = groups.get(key) ?? [];
      group.push(match);
      groups.set(key, group);
    }
    for (const group of groups.values()) {
      group.sort((a, b) => b.item.order - a.item.order);
    }
    // Keep result positions between groups, then restore the provider's
    // order within each group of same-name matches.
    return matches.map((match) => {
      const { provider, ref } = match.item;
      if (ref.suggestionGroup === undefined) return match;
      return groups.get(`${provider.id}:${ref.suggestionGroup}`)?.pop() ?? match;
    });
  }

  getItemText(item: Entry): string {
    const label = item.ref.suggestionLabel ?? item.ref.raw.slice(2, -2);
    return `${label}  (${item.provider.displayName})`;
  }

  onChooseItem(item: Entry): void {
    void this.onChoose(item);
  }
}
