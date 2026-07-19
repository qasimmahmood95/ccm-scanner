#!/usr/bin/env node
import { formatBanner, readManifest } from "./banner.js";

process.stdout.write(formatBanner(readManifest(), process.argv.slice(2)));
