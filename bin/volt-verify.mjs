#!/usr/bin/env node
/**
 * volt-verify: thin executable shim. All logic lives in dist/cli.js so it can
 * be unit-tested without spawning a process.
 */
import { runCli } from '../dist/cli.js';

const { report, exitCode } = runCli(process.argv.slice(2));
process.stdout.write(JSON.stringify(report, null, 2) + '\n');
process.exit(exitCode);
