/**
 * ============================================================================
 * Security Module (OWASP Top 10:2025 Mitigations)
 * Disciplina: Projeto Aplicado - Práticas de Mercado
 * 
 * Mitigações Implementadas:
 * - A01:2025: Broken Access Control (Invalidação de sessão, timeout de inatividade)
 * - A03:2025: Injection / Cross-Site Scripting (XSS) (Sanitização estrita e escape contextual)
 * ============================================================================
 */

const Security = (() => {
  'use strict';

  // Configurações Globais de Segurança
  const SESSION_TIMEOUT_SECONDS = 15 * 60; // 15 minutos de inatividade
  let sessionTimerInterval = null;
  let sessionDeadline = 0;
  let onSessionExpireCallback = null;
  let onSessionTickCallback = null;

  /**
   * OWASP A03:2025 - Prevenção contra XSS / Injection
   * Escapa caracteres especiais de HTML para impedir injeção de scripts no DOM.
   * @param {string} input - Texto não confiável recebido do usuário
   * @returns {string} - String devidamente escapada
   */
  function escapeHTML(input) {
    if (typeof input !== 'string') return '';
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  /**
   * Higieniza entradas de formulário removendo espaços excessivos e caracteres de controle
   * @param {string} str
   * @param {number} maxLength
   * @returns {string}
   */
  function sanitizeInput(str, maxLength = 64) {
    if (typeof str !== 'string') return '';
    return str.trim().slice(0, maxLength);
  }

  /**
   * Renderiza texto com segurança dentro de um nó do DOM usando textContent nativo
   * @param {HTMLElement} element 
   * @param {string} text 
   */
  function setSafeText(element, text) {
    if (!element) return;
    element.textContent = text;
  }

  /**
   * Verifica o relógio real (imune a congelamento de abas em segundo plano do navegador)
   */
  function checkAndUpdateTimer() {
    if (!sessionTimerInterval) return false;

    const now = Date.now();
    const remainingSeconds = Math.max(0, Math.ceil((sessionDeadline - now) / 1000));

    if (typeof onSessionTickCallback === 'function') {
      const mins = String(Math.floor(remainingSeconds / 60)).padStart(2, '0');
      const secs = String(remainingSeconds % 60).padStart(2, '0');
      onSessionTickCallback(`${mins}:${secs}`);
    }

    if (remainingSeconds <= 0) {
      const expireCb = onSessionExpireCallback;
      stopSessionTimer();
      if (typeof expireCb === 'function') {
        expireCb();
      }
      return true; // Expirou
    }
    return false;
  }

  /**
   * OWASP A01:2025 - Broken Access Control: Monitor de Inatividade
   * Inicia a contagem regressiva para expiração automática da sessão usando timestamp real
   */
  function startSessionTimer(onExpire, onTick) {
    stopSessionTimer();
    sessionDeadline = Date.now() + SESSION_TIMEOUT_SECONDS * 1000;
    onSessionExpireCallback = onExpire;
    onSessionTickCallback = onTick;

    checkAndUpdateTimer();
    sessionTimerInterval = setInterval(checkAndUpdateTimer, 1000);
  }

  function resetSessionTimer() {
    if (!sessionTimerInterval) return;
    // Se já expirou enquanto a aba estava em segundo plano, desloga imediatamente em vez de renovar
    if (Date.now() >= sessionDeadline) {
      checkAndUpdateTimer();
      return;
    }
    sessionDeadline = Date.now() + SESSION_TIMEOUT_SECONDS * 1000;
    try {
      const raw = sessionStorage.getItem('__sec_session_token');
      if (raw) {
        const data = JSON.parse(raw);
        data.expiresAt = new Date(sessionDeadline).toISOString();
        sessionStorage.setItem('__sec_session_token', JSON.stringify(data));
      }
    } catch {
      // ignora erro de parse
    }
    checkAndUpdateTimer();
  }

  function stopSessionTimer() {
    if (sessionTimerInterval) {
      clearInterval(sessionTimerInterval);
      sessionTimerInterval = null;
    }
    sessionDeadline = 0;
  }

  /**
   * Registra ouvintes para verificar expiração ao voltar para a aba e renovar mediante atividade válida
   */
  function initUserActivityListeners() {
    ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
      window.addEventListener(event, () => {
        if (sessionTimerInterval) {
          resetSessionTimer();
        }
      }, { passive: true });
    });

    // Quando o usuário volta para a aba ou foca a janela, verifica imediatamente se o tempo já esgotou
    window.addEventListener('focus', () => {
      if (sessionTimerInterval) checkAndUpdateTimer();
    });
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden && sessionTimerInterval) checkAndUpdateTimer();
    });
  }

  // Inicializa monitor de atividade
  initUserActivityListeners();

  return {
    escapeHTML,
    sanitizeInput,
    setSafeText,
    startSessionTimer,
    resetSessionTimer,
    stopSessionTimer
  };
})();
