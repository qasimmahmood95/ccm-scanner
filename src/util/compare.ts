/**
 * Locale-independent string comparison.
 *
 * `String.prototype.localeCompare` varies with the host's ICU data, which would
 * make report ordering machine-dependent. Reports must be byte-identical for a
 * given input, so ordering uses plain code-unit comparison.
 */
export function compareStrings(a: string, b: string): number {
  if (a < b) {
    return -1;
  }
  if (a > b) {
    return 1;
  }
  return 0;
}
