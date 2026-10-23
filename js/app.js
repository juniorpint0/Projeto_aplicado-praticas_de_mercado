/**
 * ============================================================================
 * Application Controller (SPA & View Orchestration)
 * Disciplina: Projeto Aplicado - Práticas de Mercado
 * 
 * Implementa:
 * - Alternância e controle de rotas seguras (Login x Dashboard Restrito)
 * - Logout funcional com expurgo de sessão
 * - Demonstração interativa de sanitização OWASP A03:2025
 * ============================================================================
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  // Elementos do DOM - Login
  const loginView = document.getElementById('login-view');
  const loginForm = document.getElementById('login-form');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const btnLogin = document.getElementById('btn-login');
  const loginAlert = document.getElementById('login-alert');
  const attemptsLeftSpan = document.getElementById('attempts-left');

  // Elementos do DOM - Área Restrita (Dashboard)
  const appView = document.getElementById('app-view');
  const authenticatedUserSpan = document.getElementById('authenticated-user');
  const sessionCountdown = document.getElementById('session-countdown');
  const btnLogout = document.getElementById('btn-logout');
  const sessionMetadataBody = document.getElementById('session-metadata-body');

  // Elementos do DOM - Laboratório de Teste XSS
  const testXssInput = document.getElementById('test-xss-input');
  const btnTestXss = document.getElementById('btn-test-xss');
  const rawOutput = document.getElementById('raw-output');
  const sanitizedOutput = document.getElementById('sanitized-output');

  /**
   * Exibe mensagens de feedback com sanitização
   */
  function showAlert(message, type = 'danger') {
    loginAlert.className = `alert alert-${type}`;
    loginAlert.textContent = message;
    loginAlert.classList.remove('hidden');
  }

  function hideAlert() {
    loginAlert.classList.add('hidden');
    loginAlert.textContent = '';
  }

  /**
   * Atualiza indicador de tentativas restantes
   */
  function updateAttemptsUI() {
    if (Auth.isLockedOut()) {
      const remainingSecs = Auth.getLockoutRemainingSeconds();
      attemptsLeftSpan.textContent = '0 (BLOQUEADO)';
      btnLogin.disabled = true;
      showAlert(`Acesso bloqueado por segurança devido a tentativas incorretas. Tente novamente em ${remainingSecs}s.`, 'warning');
      
      const interval = setInterval(() => {
        const secs = Auth.getLockoutRemainingSeconds();
        if (secs <= 0) {
          clearInterval(interval);
          btnLogin.disabled = false;
          attemptsLeftSpan.textContent = `${Auth.MAX_FAILED_ATTEMPTS}`;
          hideAlert();
        } else {
          showAlert(`Acesso bloqueado por segurança devido a tentativas incorretas. Tente novamente em ${secs}s.`, 'warning');
        }
      }, 1000);
      return;
    }

    const failed = Auth.getFailedAttempts();
    const remaining = Math.max(0, Auth.MAX_FAILED_ATTEMPTS - failed);
    attemptsLeftSpan.textContent = `${remaining}`;
    btnLogin.disabled = false;
  }

  /**
   * OWASP A01:2025 - Controle de Rotas: Renderiza Área Interna Protegida
   */
  function showProtectedView(session) {
    loginView.classList.add('hidden');
    appView.classList.remove('hidden');

    // Popula dados do usuário autenticado de forma segura (textContent)
    authenticatedUserSpan.textContent = `${session.fullName} (${session.username})`;

    // Preenche tabela de metadados da sessão
    populateSessionMetadata(session);

    // Inicia cronômetro de expiração por inatividade (15 min)
    Security.startSessionTimer(
      // Callback ao expirar
      () => {
        handleLogout('Sua sessão expirou por inatividade. Faça login novamente para continuar.');
      },
      // Callback a cada segundo
      (timeFormatted) => {
        sessionCountdown.textContent = timeFormatted;
      }
    );
  }

  /**
   * Renderiza a Tela de Login
   */
  function showLoginView(expiredMessage = null) {
    Security.stopSessionTimer();
    appView.classList.add('hidden');
    loginView.classList.remove('hidden');

    // Limpa campos sensíveis
    passwordInput.value = '';

    updateAttemptsUI();

    if (expiredMessage) {
      showAlert(expiredMessage, 'warning');
    }
  }

  /**
   * Popula tabela técnica de auditoria da sessão
   */
  function populateSessionMetadata(session) {
    sessionMetadataBody.innerHTML = '';

    const metadata = [
      { param: 'ID do Usuário', value: session.username, desc: 'Identificador único do operador' },
      { param: 'Cargo & Função', value: session.role, desc: 'Perfil com privilégios concedidos' },
      { param: 'Token de Sessão (256 bits)', value: `${session.token.substring(0, 16)}...${session.token.substring(48)}`, desc: 'Gerado criptograficamente (crypto.getRandomValues)' },
      { param: 'Timestamp de Emissão', value: new Date(session.createdAt).toLocaleString('pt-BR'), desc: 'Validação temporal da sessão' },
      { param: 'Defesa OWASP A01', value: 'Controle de Acesso em Nível de Rota', desc: 'Sessão isolada via SessionStorage' },
      { param: 'Defesa OWASP A03', value: 'Sanitização DOM + CSP Headers', desc: 'Prevenção ativa contra injeções' },
      { param: 'Defesa OWASP A07', value: 'Web Crypto SHA-256 + Rate Limit', desc: 'Proteção contra força bruta e credenciais em texto claro' }
    ];

    metadata.forEach(item => {
      const row = document.createElement('tr');

      const colParam = document.createElement('td');
      colParam.innerHTML = `<strong>${Security.escapeHTML(item.param)}</strong>`;

      const colVal = document.createElement('td');
      colVal.innerHTML = `<code>${Security.escapeHTML(item.value)}</code>`;

      const colDesc = document.createElement('td');
      colDesc.textContent = item.desc;

      row.appendChild(colParam);
      row.appendChild(colVal);
      row.appendChild(colDesc);
      sessionMetadataBody.appendChild(row);
    });
  }

  /**
   * Handler de Login
   */
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const username = Security.sanitizeInput(usernameInput.value, 32);
    const password = passwordInput.value;

    if (!username || !password) {
      showAlert('Por favor, informe o usuário e a senha.');
      return;
    }

    // Feedback visual de carregamento
    btnLogin.disabled = true;
    const btnText = btnLogin.querySelector('.btn-text');
    const spinner = btnLogin.querySelector('.btn-spinner');
    btnText.textContent = 'Autenticando...';
    spinner.classList.remove('hidden');

    try {
      const result = await Auth.login(username, password);

      if (result.success) {
        showProtectedView(result.user);
      } else {
        updateAttemptsUI();
        showAlert(result.error, result.locked ? 'warning' : 'danger');
      }
    } catch (err) {
      showAlert('Ocorreu um erro ao processar a autenticação.');
    } finally {
      btnLogin.disabled = false;
      btnText.textContent = 'Entrar no Sistema';
      spinner.classList.add('hidden');
    }
  });

  /**
   * Handler do Botão de Logout Funcional
   */
  function handleLogout(customMessage = null) {
    Auth.logout();
    showLoginView(customMessage);
  }

  btnLogout.addEventListener('click', (e) => {
    e.preventDefault();
    handleLogout('Você encerrou sua sessão com sucesso.');
  });

  /**
   * Laboratório Interativo de Validação XSS (OWASP A03:2025)
   */
  btnTestXss.addEventListener('click', () => {
    const rawVal = testXssInput.value;
    if (!rawVal) {
      rawOutput.textContent = '(digite um payload para testar)';
      sanitizedOutput.textContent = '(nenhuma entrada fornecida)';
      return;
    }

    // Exibe a entrada original escapada no bloco pre para visualização
    rawOutput.textContent = rawVal;

    // Renderização Segura com textContent nativo (mitiga execução do script)
    Security.setSafeText(sanitizedOutput, rawVal);
  });

  // ==================== INICIALIZAÇÃO DA APLICAÇÃO ====================
  // Verifica se o usuário já possui sessão válida ao carregar/recarregar a página
  const currentSession = Auth.getSession();
  if (currentSession) {
    showProtectedView(currentSession);
  } else {
    showLoginView();
  }
});
