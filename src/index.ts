/**
 * Public library surface.
 *
 * The executable entry point lives in `src/cli/` — importing this module has no
 * side effects, so the engine can be embedded as well as run from the CLI.
 */
export * from "./model/index.js";
export * from "./engine/index.js";
export * from "./report/index.js";
export { sha256Hex } from "./util/digest.js";
