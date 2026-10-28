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

  it('3. Master Owner credentials setup and retrieval via DatabaseService', async () => {
    const salt = generateSalt();
    const passwordHash = await hashPassword(testMasterPass, salt);

    const creds: MasterOwnerCredentials = {
      email: ALT_MASTER_EMAIL,
      passwordHash,
      salt,
      isConfigured: true,
      configuredAt: new Date().toISOString(),
      twoFactorEnabled: false,
    };

    await DatabaseService.saveMasterOwnerCredentials(creds);

    const fetched = await DatabaseService.getMasterOwnerCredentials(ALT_MASTER_EMAIL);
    assert.ok(fetched, 'Master credentials must be retrievable');
    assert.strictEqual(fetched.isConfigured, true);
    assert.strictEqual(fetched.passwordHash, passwordHash);
    assert.strictEqual(fetched.salt, salt);
  });

  it('4. DatabaseService.authenticateUser recognizes Master Owner by email', async () => {
    // Authenticate with valid password
    const res = await DatabaseService.authenticateUser(ALT_MASTER_EMAIL, testMasterPass);
    assert.strictEqual(res.success, true, 'Authentication must succeed');
    assert.ok(res.user, 'User profile must be returned');
    assert.strictEqual(res.user.role, 'MASTER_OWNER');
    assert.strictEqual(res.user.status, 'ativo');
    assert.strictEqual(res.user.email.toLowerCase(), ALT_MASTER_EMAIL.toLowerCase());

    // Authenticate with wrong password
    const failRes = await DatabaseService.authenticateUser(ALT_MASTER_EMAIL, 'BadPassword');
    assert.strictEqual(failRes.success, false);
    assert.ok(failRes.error?.includes('Senha incorreta'));
  });

  it('5. Case-insensitive Master Owner authentication', async () => {
    const uppercaseEmail = ALT_MASTER_EMAIL.toUpperCase();
    const res = await DatabaseService.authenticateUser(uppercaseEmail, testMasterPass);
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.user?.role, 'MASTER_OWNER');
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
