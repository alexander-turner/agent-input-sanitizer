/**
 * Shared test helpers.
 */

/**
 * fast-check run options. A fixed seed is replayed when FC_REPRODUCIBLE=1 (set
 * by the coverage/CI job that needs a stable oracle) so a green run stays green
 * and any failure is reproducible from the logged seed; otherwise fast-check
 * randomizes so PRs keep surfacing new counterexamples.
 * @param {import("fast-check").Parameters} [overrides]
 */
export function fcRunOptions(overrides = {}) {
  const reproducible = process.env.FC_REPRODUCIBLE === "1";
  return {
    verbose: false,
    ...(reproducible ? { seed: 0x5eed1234 } : {}),
    ...overrides,
  };
}

/** String.fromCodePoint shorthand used throughout the Unicode tests. */
export const cp = (codePoint) => String.fromCodePoint(codePoint);
