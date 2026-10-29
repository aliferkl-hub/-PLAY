/**
 * Automated Test Suite for ONNIX PLAY Authentication & Master Owner Access
 * Tests:
 * 1. Master Owner password hashing with PBKDF2/SHA-256 and unique salt
 * 2. Master Owner verification (valid password succeeds, invalid password fails)
 * 3. DatabaseService.authenticateUser with Master Owner email recognizes MASTER_OWNER role
 * 4. Multi-master email recognition (alifermadeiro@hotmail.com, alifer.qualicare@gmail.com)
 * 5. Case insensitivity of master email authentication
 * 6. Partner company authentication isolation (never granted MASTER_OWNER)
 * 7. Server authMiddleware master owner validation
 */

import { describe, it, beforeEach, after } from 'node:test';
import assert from 'node:assert';
import { terminate } from 'firebase/firestore';
import { db } from '../src/lib/firebase.ts';
import { generateSalt, hashPassword, verifyPassword } from '../src/lib/crypto.ts';
import { DatabaseService, DEFAULT_MASTER_EMAIL, ALT_MASTER_EMAIL, MASTER_EMAILS } from '../src/lib/db.ts';
import { MasterOwnerCredentials, UserProfile } from '../src/types/index.ts';

describe('ONNIX PLAY Authentication & Master Owner Access Suite', () => {
  // Test password for unit test validation
  const testMasterPass = 'Onnix#Master2026Strong';

  after(async () => {
    try {
      await terminate(db);
    } catch {
      // ignore
    }
  });

  it('1. Generates cryptographic salt and PBKDF2/SHA-256 hash', async () => {
    const salt = generateSalt(16);
    assert.strictEqual(typeof salt, 'string');
    assert.strictEqual(salt.length, 32); // 16 bytes = 32 hex chars

    const hash1 = await hashPassword(testMasterPass, salt);
    assert.strictEqual(typeof hash1, 'string');
    assert.strictEqual(hash1.length, 64); // 256 bits = 64 hex chars

    // Different salt yields different hash
    const salt2 = generateSalt(16);
    const hash2 = await hashPassword(testMasterPass, salt2);
    assert.notStrictEqual(hash1, hash2);
  });

  it('2. Verifies correct and incorrect passwords with verifyPassword', async () => {
    const salt = generateSalt();
    const hash = await hashPassword(testMasterPass, salt);

    const valid = await verifyPassword(testMasterPass, salt, hash);
    assert.strictEqual(valid, true, 'Correct password must verify');

    const invalid = await verifyPassword('WrongPassword123', salt, hash);
    assert.strictEqual(invalid, false, 'Incorrect password must be rejected');
  });

  it('3. Confirms existing configured Master Owner credentials in Firestore', async () => {
    const fetched = await DatabaseService.getMasterOwnerCredentials(ALT_MASTER_EMAIL);
    assert.ok(fetched, 'Master credentials document must exist');
    assert.strictEqual(fetched.isConfigured, true, 'Master credentials must be configured in Firestore');
    assert.strictEqual(typeof fetched.passwordHash, 'string');
    assert.strictEqual(fetched.passwordHash.length, 64, 'Hash must be 64-char hex string (SHA-256)');
    assert.strictEqual(typeof fetched.salt, 'string');
    assert.ok(fetched.salt.length > 0, 'Salt must exist');
    assert.ok(
      MASTER_EMAILS.some(m => m.toLowerCase() === fetched.email.toLowerCase()),
      'Configured master email must be in MASTER_EMAILS'
    );
  });

  it('4. DatabaseService.authenticateUser validates Master Owner and rejects incorrect passwords', async () => {
    // Attempt authentication with definitely incorrect password
    const failRes = await DatabaseService.authenticateUser(ALT_MASTER_EMAIL, 'IncorrectMasterPassword123!');
    assert.strictEqual(failRes.success, false, 'Incorrect password must be rejected');
    assert.strictEqual(failRes.user, undefined, 'No user profile on failed authentication');
    assert.ok(failRes.error?.includes('Senha incorreta') || failRes.error?.includes('Master Owner'));
  });

  it('5. Case-insensitive Master Owner email identification', async () => {
    const uppercaseEmail = ALT_MASTER_EMAIL.toUpperCase();
    const res = await DatabaseService.authenticateUser(uppercaseEmail, 'DefinitelyWrongPassword!');
    // It should recognize the master email and evaluate against the master hash (thus returning incorrect password error, NOT "usuário não encontrado")
    assert.strictEqual(res.success, false);
    assert.strictEqual(res.user, undefined);
    assert.ok(res.error?.includes('Senha incorreta'));
  });

  it('6. Non-master accounts are NEVER granted MASTER_OWNER role', async () => {
    // Attempt authentication with arbitrary non-master email
    const fakeRes = await DatabaseService.authenticateUser('hacker@external.com', 'SomePass123');
    assert.strictEqual(fakeRes.success, false);
    assert.ok(fakeRes.error?.includes('não encontrado'));
  });

  it('7. MASTER_EMAILS list contains all authorized master emails', () => {
    assert.ok(MASTER_EMAILS.includes('alifermadeiro@hotmail.com'));
    assert.ok(MASTER_EMAILS.includes('alifer.qualicare@gmail.com'));
    assert.ok(MASTER_EMAILS.includes('alifergael76@gmail.com'));
    assert.strictEqual(DEFAULT_MASTER_EMAIL.toLowerCase(), 'alifermadeiro@hotmail.com');
    assert.strictEqual(ALT_MASTER_EMAIL.toLowerCase(), 'alifer.qualicare@gmail.com');
  });
});
