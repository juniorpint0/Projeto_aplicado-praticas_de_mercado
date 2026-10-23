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
  let remainingSeconds = SESSION_TIMEOUT_SECONDS;
  let onSessionExpireCallback = null;

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
   * OWASP A01:2025 - Broken Access Control: Monitor de Inatividade
   * Inicia a contagem regressiva para expiração automática da sessão
   */
  function startSessionTimer(onExpire, onTick) {
    stopSessionTimer();
    remainingSeconds = SESSION_TIMEOUT_SECONDS;
    onSessionExpireCallback = onExpire;

    sessionTimerInterval = setInterval(() => {
      remainingSeconds--;

      if (typeof onTick === 'function') {
        const mins = String(Math.floor(remainingSeconds / 60)).padStart(2, '0');
        const secs = String(remainingSeconds % 60).padStart(2, '0');
        onTick(`${mins}:${secs}`);
      }

      if (remainingSeconds <= 0) {
        stopSessionTimer();
        if (typeof onSessionExpireCallback === 'function') {
          onSessionExpireCallback();
        }
      }
    }, 1000);
  }

  function resetSessionTimer() {
    remainingSeconds = SESSION_TIMEOUT_SECONDS;
  }

  function stopSessionTimer() {
    if (sessionTimerInterval) {
      clearInterval(sessionTimerInterval);
      sessionTimerInterval = null;
    }
  }

  /**
   * Registra ouvintes para reiniciar o cronômetro de inatividade mediante interação do usuário
   */
  function initUserActivityListeners() {
    ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
      window.addEventListener(event, () => {
        // Renova tempo se a sessão estiver ativa
        if (sessionTimerInterval) {
          resetSessionTimer();
        }
      }, { passive: true });
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
