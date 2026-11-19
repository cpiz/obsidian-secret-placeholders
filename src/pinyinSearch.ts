import { match } from "pinyin-pro";

export function preparePinyinSearch(query: string): ((label: string) => boolean) | null {
  const normalized = query.trim().toLowerCase();
  if (!/[a-z]/.test(normalized)) return null;
  return (label) => /\p{Script=Han}/u.test(label) &&
    match(label, normalized, { continuous: true, v: true }) !== null;
}
