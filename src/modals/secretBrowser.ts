// Search across known secrets from every enabled provider. Used by
// the "Browse and insert" / "Browse and copy" commands so the user doesn't
// have to remember exact paths.

import { App, FuzzySuggestModal, Notice, type FuzzyMatch, type SearchMatches } from "obsidian";
import { t } from "../i18n";
import { preparePinyinSearch } from "../pinyinSearch";
import type SecretPlaceholdersPlugin from "../main";
import type { Provider, ProviderRef } from "../providers/types";

interface Entry {
  provider: Provider;
  ref: ProviderRef;
  order: number;
}

function highlightPinyin(label: string, positions: number[]): SearchMatches {
  const ranges: SearchMatches = [];
  for (const start of positions) {
    const end = start + ((label.codePointAt(start) ?? 0) > 0xffff ? 2 : 1);
    const last = ranges[ranges.length - 1];
    if (last && start <= last[1]) {
      last[1] = Math.max(last[1], end);
    } else {
      ranges.push([start, end]);
    }
  }
  return ranges;
}

export class SecretBrowserModal extends FuzzySuggestModal<Entry> {
  private entries: Entry[] = [];

  constructor(
    app: App,
    private plugin: SecretPlaceholdersPlugin,
    private onChoose: (entry: Entry) => void | Promise<void>,
    private chooseProject = false,
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
    const text = query.trim();
    if (!text) {
      return this.entries.map((item) => ({ item, match: { score: 0, matches: [] } }));
    }
    const literal = new RegExp(text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "iu");
    const compact = /^[a-z0-9 ._-]+$/i.test(text) ? text.replace(/[ ._-]/g, "") : "";
    const separated = compact.length > 1
      ? new RegExp(compact.split("").join("[ ._-]*"), "i")
      : null;
    const fullPinyin = preparePinyinSearch(query, true);
    const matchesPinyin = preparePinyinSearch(query);
    const matches: FuzzyMatch<Entry>[] = [];
    for (const item of this.entries) {
      const label = this.candidateLabel(item);
      const direct = literal.exec(label);
      if (direct) {
        matches.push({ item, match: { score: 4, matches: [[direct.index, direct.index + direct[0].length]] } });
        continue;
      }

      // Search the title and path separately from the field and display metadata.
      const location = label.split("#", 1)[0];
      const full = fullPinyin?.(location);
      if (full) {
        matches.push({ item, match: { score: 3, matches: highlightPinyin(label, full) } });
        continue;
      }
      const acrossSeparators = separated?.exec(location);
      if (acrossSeparators) {
        const { index } = acrossSeparators;
        matches.push({ item, match: { score: 2, matches: [[index, index + acrossSeparators[0].length]] } });
        continue;
      }
      const initials = matchesPinyin?.(location);
      if (initials) {
        matches.push({ item, match: { score: 1, matches: highlightPinyin(label, initials) } });
      }
    }

    matches.sort((a, b) => b.match.score - a.match.score);
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
    return `${this.candidateLabel(item)}  (${item.provider.displayName})`;
  }

  private candidateLabel(item: Entry): string {
    const { ref } = item;
    if (this.chooseProject && ref.projectLabel !== undefined) return ref.projectLabel;
    return ref.suggestionLabel ?? ref.raw.slice(2, -2);
  }

  onChooseItem(item: Entry): void {
    void this.onChoose(item);
  }
}

class SecretFieldPicker extends FuzzySuggestModal<ProviderRef> {
  constructor(
    app: App,
    private refs: ProviderRef[],
    private onChoose: (ref: ProviderRef) => void,
  ) {
    super(app);
    this.setPlaceholder(t("modal.secretBrowser.fieldPlaceholder"));
  }

  getItems(): ProviderRef[] {
    return this.refs;
  }

  getItemText(ref: ProviderRef): string {
    return ref.parts.field;
  }

  onChooseItem(ref: ProviderRef): void {
    this.onChoose(ref);
  }
}

export async function chooseProjectField(
  app: App,
  provider: Provider,
  ref: ProviderRef,
  select: (ref: ProviderRef) => void,
  canSelect = () => true,
): Promise<void> {
  if (!provider.listFields) {
    if (canSelect()) select(ref);
    return;
  }
  try {
    const fields = await provider.listFields(ref);
    if (!canSelect()) return;
    if (fields.length === 0) {
      new Notice(t("modal.secretBrowser.noFields"));
    } else if (fields.length === 1) {
      select(fields[0]);
    } else {
      new SecretFieldPicker(app, fields, (field) => {
        if (canSelect()) select(field);
      }).open();
    }
  } catch (e) {
    if (canSelect()) new Notice(t("notice.readFailed", { msg: (e as Error).message }));
  }
}
