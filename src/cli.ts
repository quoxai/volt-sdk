/**
 * volt-verify CLI (VERIFICATION.md section 10, SPEC section 18.2).
 *
 * Verifies a bundle directory or an explicit manifest/events file pair and
 * prints the verification report as JSON. Exit codes:
 *   0 = PASS
 *   1 = FAIL (verification failed)
 *   2 = ERROR (unreadable bundle / IO)
 */
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, isAbsolute, resolve } from 'node:path';
import { createPublicKey } from 'node:crypto';
import { verifyBundle, type AttachmentReader, type VerifyOptions } from './verify.js';
import type { VerificationReport } from './types.js';

export interface CliResult {
  report: VerificationReport;
  exitCode: 0 | 1 | 2;
}

interface ParsedArgs {
  bundleDir?: string;
  manifestPath?: string;
  eventsPath?: string;
  strict: boolean;
  requireSignatures: boolean;
  pubkeyPath?: string;
  help: boolean;
}

const USAGE = `volt-verify: verify a VOLT v0.1 Evidence Bundle

Usage:
  volt-verify <bundle-dir>
  volt-verify --manifest <manifest.json> --events <events.ndjson>

Options:
  --manifest <path>       Path to manifest.json (pairs with --events)
  --events <path>         Path to events.ndjson (pairs with --manifest)
  --pubkey <path>         PEM Ed25519 public key for signature verification
  --require-signatures    Fail if the bundle has no verifiable signature
  --no-strict             Permissive mode (warn on seq gaps instead of failing)
  -h, --help              Show this help

Exit codes: 0 = PASS, 1 = FAIL, 2 = ERROR`;

function parseArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = { strict: true, requireSignatures: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '-h':
      case '--help':
        parsed.help = true;
        break;
      case '--manifest':
        parsed.manifestPath = argv[++i];
        break;
      case '--events':
        parsed.eventsPath = argv[++i];
        break;
      case '--pubkey':
        parsed.pubkeyPath = argv[++i];
        break;
      case '--require-signatures':
        parsed.requireSignatures = true;
        break;
      case '--no-strict':
        parsed.strict = false;
        break;
      case '--strict':
        parsed.strict = true;
        break;
      default:
        if (!arg.startsWith('-') && !parsed.bundleDir) {
          parsed.bundleDir = arg;
        }
        break;
    }
  }
  return parsed;
}

function makeAttachmentReader(root: string): AttachmentReader {
  return (ref) => {
    const p = isAbsolute(ref.path) ? ref.path : join(root, ref.path);
    try {
      return new Uint8Array(readFileSync(p));
    } catch {
      return null;
    }
  };
}

/**
 * Run the CLI logic. Pure with respect to process state: returns the report
 * and the exit code rather than calling process.exit, so it is unit-testable.
 */
export function runCli(argv: string[]): CliResult {
  const args = parseArgs(argv);

  if (args.help) {
    return { report: { result: 'ERROR', reason: 'HELP', details: { usage: USAGE } }, exitCode: 2 };
  }

  let manifestPath: string;
  let eventsPath: string;
  let bundleRoot: string;

  if (args.manifestPath && args.eventsPath) {
    manifestPath = args.manifestPath;
    eventsPath = args.eventsPath;
    bundleRoot = resolve(manifestPath, '..');
  } else if (args.bundleDir) {
    if (!existsSync(args.bundleDir) || !statSync(args.bundleDir).isDirectory()) {
      return {
        report: { result: 'ERROR', reason: 'BUNDLE_UNREADABLE', details: { message: `not a directory: ${args.bundleDir}` } },
        exitCode: 2,
      };
    }
    bundleRoot = args.bundleDir;
    manifestPath = join(args.bundleDir, 'manifest.json');
    eventsPath = ''; // resolved from manifest below
  } else {
    return { report: { result: 'ERROR', reason: 'NO_INPUT', details: { usage: USAGE } }, exitCode: 2 };
  }

  let manifestJson: string;
  try {
    manifestJson = readFileSync(manifestPath, 'utf8');
  } catch (err) {
    return {
      report: { result: 'ERROR', reason: 'MANIFEST_MISSING', details: { message: (err as Error).message } },
      exitCode: 2,
    };
  }

  // Resolve events file from the manifest when running against a directory.
  if (!eventsPath) {
    let eventsFile = 'events.ndjson';
    try {
      const m = JSON.parse(manifestJson) as { events_file?: string };
      if (typeof m.events_file === 'string' && m.events_file.length > 0) eventsFile = m.events_file;
    } catch {
      /* verifyBundle will report MANIFEST_UNREADABLE */
    }
    eventsPath = join(bundleRoot, eventsFile);
  }

  let eventsNdjson: string;
  try {
    eventsNdjson = readFileSync(eventsPath, 'utf8');
  } catch (err) {
    return {
      report: { result: 'ERROR', reason: 'EVENTS_FILE_UNREADABLE', details: { message: (err as Error).message } },
      exitCode: 2,
    };
  }

  const options: VerifyOptions = {
    strict: args.strict,
    requireSignatures: args.requireSignatures,
    attachmentReader: makeAttachmentReader(bundleRoot),
  };

  if (args.pubkeyPath) {
    try {
      const pem = readFileSync(args.pubkeyPath, 'utf8');
      options.keyProvider = { publicKey: createPublicKey(pem) };
    } catch (err) {
      return {
        report: { result: 'ERROR', reason: 'PUBKEY_UNREADABLE', details: { message: (err as Error).message } },
        exitCode: 2,
      };
    }
  }

  const report = verifyBundle({ manifestJson, eventsNdjson }, options);
  const exitCode: 0 | 1 | 2 = report.result === 'PASS' ? 0 : report.result === 'FAIL' ? 1 : 2;
  return { report, exitCode };
}
