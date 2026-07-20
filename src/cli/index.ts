#!/usr/bin/env node
/**
 * The executable shim. Unconditional by design — see the note in `main.ts`
 * about why guarding on `process.argv[1]` breaks an npm-installed binary.
 */
import { runCli } from "./main.js";

process.exitCode = runCli(process.argv.slice(2));
