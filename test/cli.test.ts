import { describe, it, expect } from 'vitest';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runCli } from '../src/cli.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'conformance', 'fixtures');
const dir = (n: string) => join(FIX, n);

describe('volt-verify CLI (exit codes 0/1/2)', () => {
  it('exit 0 + PASS for a valid bundle directory', () => {
    const { report, exitCode } = runCli([dir('valid-simple')]);
    expect(exitCode).toBe(0);
    expect(report.result).toBe('PASS');
  });

  it('exit 0 for a signed bundle (verifies via embedded key)', () => {
    const { exitCode, report } = runCli([dir('valid-signed')]);
    expect(exitCode).toBe(0);
    if (report.result === 'PASS') expect(report.signatures_verified).toBe(true);
  });

  it('exit 1 + FAIL for a tampered bundle', () => {
    const { report, exitCode } = runCli([dir('tamper-modified-event')]);
    expect(exitCode).toBe(1);
    expect(report.result).toBe('FAIL');
  });

  it('exit 2 + ERROR for an unreadable bundle (missing directory)', () => {
    const { report, exitCode } = runCli([dir('does-not-exist')]);
    expect(exitCode).toBe(2);
    expect(report.result).toBe('ERROR');
  });

  it('accepts an explicit --manifest / --events file pair', () => {
    const { exitCode } = runCli(['--manifest', join(dir('valid-simple'), 'manifest.json'), '--events', join(dir('valid-simple'), 'events.ndjson')]);
    expect(exitCode).toBe(0);
  });

  it('exit 1 for a bad signature when a --pubkey is supplied', () => {
    const { report, exitCode } = runCli([dir('tamper-bad-signature'), '--pubkey', join(dir('tamper-bad-signature'), 'pubkey.pem')]);
    expect(exitCode).toBe(1);
    if (report.result === 'FAIL') expect(report.reason).toBe('SIGNATURE_INVALID');
  });

  it('exit 2 with usage on --help', () => {
    const { exitCode, report } = runCli(['--help']);
    expect(exitCode).toBe(2);
    expect(report.result).toBe('ERROR');
  });
});
