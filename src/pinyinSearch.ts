import { match } from "pinyin-pro";

export function preparePinyinSearch(
  query: string,
  fullSyllables = false,
): ((label: string) => number[] | null) | null {
  const normalized = query.trim().toLowerCase();
  if (!/[a-z]/.test(normalized)) return null;
  return (label) => {
    if (!/\p{Script=Han}/u.test(label)) return null;
    return match(label, normalized, {
      continuous: true,
      v: true,
      precision: fullSyllables ? "every" : "first",
      lastPrecision: fullSyllables ? "every" : "start",
    });
  };
}
