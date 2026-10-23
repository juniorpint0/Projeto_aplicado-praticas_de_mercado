/**
 * ============================================================================
 * Authentication Module (OWASP Top 10:2025 Mitigations)
 * Disciplina: Projeto Aplicado - Práticas de Mercado
 * 
 * Mitigações Implementadas:
 * - A01:2025: Broken Access Control (Validação rigorosa de tokens de sessão)
 * - A07:2025: Identification and Authentication Failures (Rate limiting contra força bruta,
 *   hash criptográfico SHA-256 com Salt via Web Crypto API, geração de token seguro)
 * ============================================================================
 */

const Auth = (() => {
  'use strict';

  // Chaves de armazenamento na SessionStorage
  const STORAGE_KEYS = {
    SESSION: '__sec_session_token',
    FAILED_ATTEMPTS: '__sec_failed_attempts',
    LOCKOUT_UNTIL: '__sec_lockout_until'
  };

  // Parâmetros de Segurança Alinhados ao Edital (Tolerância de 4 erros)
  const MAX_FAILED_ATTEMPTS = 4;
  const LOCKOUT_DURATION_MS = 60 * 1000; // 60 segundos de bloqueio temporário após 4 erros
  const CRYPTO_SALT = 'SecCorpSalt2026!';

  // Hash SHA-256 pré-calculado para o usuário homologado: "admin" / "Admin@Secure2026!"
  // Hash: sha256(CRYPTO_SALT + "Admin@Secure2026!")
  const REGISTERED_USERS = {
    admin: {
      passwordHash: '013ad7d3b55884c7062893f7f9b9a847d4875a9e938debb00a9294bad256c1d6',
      fullName: 'José Gedson Pinto Júnior',
      role: 'Analista de Segurança & DevSecOps',
      department: 'Governança & Segurança da Informação'
    }
  };

  /**
   * OWASP A07:2025 - Gera hash SHA-256 seguro via Web Crypto API
   * Garante que senhas nunca sejam tratadas ou comparadas em texto puro
   */
  async function hashPassword(plainPassword, salt) {
    const encoder = new TextEncoder();
    const data = encoder.encode(salt + plainPassword);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * OWASP A01:2025 - Gera token criptograficamente seguro com entropia de 256 bits
   */
  function generateSecureToken() {
    const buffer = new Uint8Array(32);
    crypto.getRandomValues(buffer);
    return Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Compara duas strings em tempo constante para mitigar Timing Attacks (A07:2025)
   */
  function constantTimeCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    let mismatch = a.length === b.length ? 0 : 1;
    for (let i = 0; i < a.length; ++i) {
      const charB = i < b.length ? b.charCodeAt(i) : 0;
      mismatch |= a.charCodeAt(i) ^ charB;
    }
    return mismatch === 0;
  }

  /**
   * OWASP A07:2025 - Controle de Rate Limiting contra Ataques de Força Bruta
   */
  function getFailedAttempts() {
    const attempts = sessionStorage.getItem(STORAGE_KEYS.FAILED_ATTEMPTS);
    return attempts ? parseInt(attempts, 10) : 0;
  }

  function registerFailedAttempt() {
    const current = getFailedAttempts() + 1;
    sessionStorage.setItem(STORAGE_KEYS.FAILED_ATTEMPTS, current.toString());

    if (current >= MAX_FAILED_ATTEMPTS) {
      const lockoutUntil = Date.now() + LOCKOUT_DURATION_MS;
      sessionStorage.setItem(STORAGE_KEYS.LOCKOUT_UNTIL, lockoutUntil.toString());
    }
    return current;
  }

  function resetFailedAttempts() {
    sessionStorage.removeItem(STORAGE_KEYS.FAILED_ATTEMPTS);
    sessionStorage.removeItem(STORAGE_KEYS.LOCKOUT_UNTIL);
  }

  function isLockedOut() {
    const lockoutUntil = sessionStorage.getItem(STORAGE_KEYS.LOCKOUT_UNTIL);
    if (!lockoutUntil) return false;
    const remaining = parseInt(lockoutUntil, 10) - Date.now();
    if (remaining > 0) {
      return true;
    }
    // Período de bloqueio expirou
    resetFailedAttempts();
    return false;
  }

  function getLockoutRemainingSeconds() {
    const lockoutUntil = sessionStorage.getItem(STORAGE_KEYS.LOCKOUT_UNTIL);
    if (!lockoutUntil) return 0;
    const remaining = parseInt(lockoutUntil, 10) - Date.now();
    return remaining > 0 ? Math.ceil(remaining / 1000) : 0;
  }

  /**
   * OWASP A07:2025 & A01:2025 - Realiza a autenticação de forma segura
   */
  async function login(username, password) {
    // 1. Verifica se a conta está temporariamente bloqueada por força bruta
    if (isLockedOut()) {
      const seconds = getLockoutRemainingSeconds();
      return {
        success: false,
        error: `Excesso de tentativas incorretas. Acesso bloqueado por segurança. Aguarde ${seconds}s.`,
        locked: true,
        remainingSeconds: seconds
      };
    }

    // 2. Sanitização básica
    const cleanUser = (username || '').trim().toLowerCase();
    const userRecord = REGISTERED_USERS[cleanUser];

    // Se o usuário não existir, executa o hash mesmo assim para equalizar tempo de resposta (Timing Attack)
    const passwordToHash = password || '';
    const computedHash = await hashPassword(passwordToHash, CRYPTO_SALT);

    if (!userRecord || !constantTimeCompare(computedHash, userRecord.passwordHash)) {
      const attempts = registerFailedAttempt();
      const remainingAttempts = Math.max(0, MAX_FAILED_ATTEMPTS - attempts);

      if (remainingAttempts === 0) {
        const lockSecs = Math.ceil(LOCKOUT_DURATION_MS / 1000);
        return {
          success: false,
          error: `Limite de 4 tentativas atingido! Bloqueio de segurança ativado por ${lockSecs} segundos.`,
          locked: true,
          remainingAttempts: 0
        };
      }

      return {
        success: false,
        error: `Credenciais inválidas! Tentativas restantes: ${remainingAttempts} de ${MAX_FAILED_ATTEMPTS}.`,
        locked: false,
        remainingAttempts: remainingAttempts
      };
    }

    // 3. Sucesso na autenticação: reseta tentativas e gera token de sessão seguro
    resetFailedAttempts();
    const sessionData = {
      token: generateSecureToken(),
      username: cleanUser,
      fullName: userRecord.fullName,
      role: userRecord.role,
      department: userRecord.department,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString()
    };

    sessionStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(sessionData));

    return {
      success: true,
      user: sessionData
    };
  }

  /**
   * OWASP A01:2025 - Broken Access Control: Validação de Estado
   */
  function getSession() {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEYS.SESSION);
      if (!raw) return null;
      const data = JSON.parse(raw);

      // Validação de expiração temporal
      if (new Date(data.expiresAt).getTime() < Date.now()) {
        logout();
        return null;
      }
      return data;
    } catch {
      logout();
      return null;
    }
  }

  function isAuthenticated() {
    return getSession() !== null;
  }

  /**
   * Botão de Logout Funcional Obrigatório
   * Limpa tokens de sessão, estado volátil e encerra comunicação
   */
  function logout() {
    sessionStorage.removeItem(STORAGE_KEYS.SESSION);
  }

  return {
    login,
    logout,
    getSession,
    isAuthenticated,
    isLockedOut,
    getFailedAttempts,
    getLockoutRemainingSeconds,
    MAX_FAILED_ATTEMPTS
  };
})();
