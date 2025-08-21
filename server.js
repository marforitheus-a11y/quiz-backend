// ==================================================================
// ARQUIVO admin.js (VERSÃO FINAL, COMPLETA E CORRIGIDA)
// ==================================================================

// --- LÓGICA DE PROTEÇÃO (EXECUTADA IMEDIATAMENTE PARA PROTEGER A PÁGINA) ---
(function authenticateAdminPage() {
    // Função auxiliar para decodificar o token e ler seu conteúdo
    function parseJwt(token) {
        try {
            return JSON.parse(atob(token.split('.')[1]));
        } catch (e) {
            return null;
        }
    }

    const token = localStorage.getItem('token');
    let isAdmin = false;

    if (token) {
        const payload = parseJwt(token);
        if (payload && payload.role === 'admin') {
            isAdmin = true;
        }
    }

    // Se o usuário não for um admin, ele é redirecionado e o script para de ser executado
    if (!isAdmin) {
        alert('Acesso negado. Esta área é exclusiva para administradores.');
        window.location.href = 'index.html';
        throw new Error("Acesso não autorizado."); // Impede a execução do resto do script
    }
})();


// --- CÓDIGO PRINCIPAL DO PAINEL DE ADMIN ---

// Variáveis globais usadas em várias funções
const token = localStorage.getItem('token');
const username = localStorage.getItem('username');
const API_URL = 'https://quiz-api-z4ri.onrender.com'; // ⚠️ VERIFIQUE SE ESTA É SUA URL CORRETA

// O CÓDIGO ABAIXO SÓ EXECUTA DEPOIS QUE O HTML DA PÁGINA ESTIVER PRONTO
document.addEventListener('DOMContentLoaded', () => {
    // --- SELETORES DE ELEMENTOS ---
    const themeForm = document.getElementById('theme-form');
    const userForm = document.getElementById('user-form');
    const sessionsTableBody = document.getElementById('sessions-table-body');
    const usersTableBody = document.getElementById('users-table-body');
    const reportsTableBody = document.getElementById('reports-table-body');
    const logoutBtn = document.getElementById('logout-btn');
    const submitThemeBtn = document.getElementById('submit-theme-btn');
    const progressContainer = document.getElementById('upload-progress-container');
    const themeStatus = document.getElementById('theme-status');
    const progressBarFill = document.getElementById('progress-bar-fill');

    // --- CARREGAMENTO INICIAL DOS DADOS DO PAINEL ---
    loadActiveSessions();
    loadUsers();
    loadReports();

    // --- EVENT LISTENERS (FUNCIONALIDADES DOS BOTÕES E FORMULÁRIOS) ---

    // Lógica do botão de Sair
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            try {
                await fetch(`${API_URL}/logout`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username })
                });
            } finally {
                localStorage.removeItem('token');
                localStorage.removeItem('username');
                window.location.href = 'index.html';
            }
        });
    }

    // Lógica do formulário de criar TEMA (com barra de carregamento)
    if (themeForm) {
        themeForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            // 1. Prepara a UI para o carregamento
            submitThemeBtn.disabled = true;
            submitThemeBtn.textContent = 'Processando...';
            progressContainer.style.display = 'block';
            themeStatus.textContent = 'Enviando PDF...';
            progressBarFill.style.width = '20%';

            const formData = new FormData();
            formData.append('themeName', e.target.themeName.value);
            formData.append('pdfFile', e.target.pdfFile.files[0]);

            try {
                // 2. Simula o progresso enquanto a API trabalha
                themeStatus.textContent = 'Analisando o texto e gerando questões com a IA (isso pode levar até 30s)...';
                progressBarFill.style.width = '60%';

                const response = await fetch(`${API_URL}/admin/themes`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` },
                    body: formData,
                });

                const result = await response.json();
                if (!response.ok) throw new Error(result.message);

                // 3. Processo concluído com sucesso
                themeStatus.textContent = result.message;
                themeStatus.style.color = 'var(--success-color)';
                progressBarFill.style.width = '100%';
                themeForm.reset();

            } catch (error) {
                // 4. Processo falhou
                themeStatus.textContent = `Erro: ${error.message}`;
                themeStatus.style.color = 'var(--danger-color)';
                progressBarFill.style.width = '100%';
                progressBarFill.style.backgroundColor = 'var(--danger-color)';
            } finally {
                // 5. Reabilita o botão após um tempo, independentemente do resultado
                setTimeout(() => {
                    submitThemeBtn.disabled = false;
                    submitThemeBtn.textContent = 'Enviar e Gerar Questões';
                    progressContainer.style.display = 'none';
                    progressBarFill.style.width = '0%';
                    progressBarFill.style.backgroundColor = 'var(--primary-color)'; // Reseta a cor da barra
                }, 4000); // Espera 4 segundos para o usuário ler a mensagem
            }
        });
    }

    // Lógica do formulário de criar USUÁRIO
    if (userForm) {
        userForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const userStatus = document.getElementById('user-status');
            userStatus.textContent = 'Criando usuário...';

            const userData = {
                username: e.target.username.value,
                password: e.target.password.value,
                subscription_expires_at: e.target.subscription.value || null,
            };

            try {
                const response = await fetch(`${API_URL}/admin/users`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify(userData),
                });
                const result = await response.json();
                if (!response.ok) throw new Error(result.message);
                
                userStatus.textContent = result.message;
                userStatus.style.color = 'var(--success-color)';
                userForm.reset();
                loadUsers(); // Atualiza a lista de usuários na tela
            } catch (error) {
                userStatus.textContent = `Erro: ${error.message}`;
                userStatus.style.color = 'var(--danger-color)';
            }
        });
    }

    // --- FUNÇÕES DE CARREGAMENTO DE DADOS ---
    async function loadActiveSessions() {
        if (!sessionsTableBody) return;
        try {
            const response = await fetch(`${API_URL}/admin/sessions`, { headers: { 'Authorization': `Bearer ${token}` } });
            const sessions = await response.json();
            sessionsTableBody.innerHTML = '';
            for (const username in sessions) {
                const session = sessions[username];
                const loginTime = new Date(session.loginTime).toLocaleTimeString('pt-BR');
                const row = `<tr><td>${username}</td><td>${session.role}</td><td>${loginTime}</td></tr>`;
                sessionsTableBody.innerHTML += row;
            }
        } catch (error) {
            console.error('Erro ao carregar sessões:', error);
            sessionsTableBody.innerHTML = '<tr><td colspan="3">Erro ao carregar sessões.</td></tr>';
        }
    }

    async function loadUsers() {
        if (!usersTableBody) return;
        try {
            const response = await fetch(`${API_URL}/admin/users`, { headers: { 'Authorization': `Bearer ${token}` } });
            const users = await response.json();
            usersTableBody.innerHTML = '';
            users.forEach(user => {
                const expirationDate = user.subscription_expires_at ? new Date(user.subscription_expires_at).toLocaleDateString('pt-BR') : 'N/A';
                const row = `
                    <tr>
                        <td>${user.id}</td>
                        <td>${user.username}</td>
                        <td>${expirationDate}</td>
                        <td><button class="btn-delete" data-userid="${user.id}">Apagar</button></td>
                    </tr>
                `;
                usersTableBody.innerHTML += row;
            });

            document.querySelectorAll('.btn-delete').forEach(button => {
                button.addEventListener('click', (e) => {
                    const userId = e.target.dataset.userid;
                    deleteUser(userId);
                });
            });
        } catch (error) {
            console.error('Erro ao carregar usuários:', error);
            usersTableBody.innerHTML = '<tr><td colspan="4">Erro ao carregar usuários.</td></tr>';
        }
    }

    async function loadReports() {
        if (!reportsTableBody) return;
        try {
            const response = await fetch(`${API_URL}/admin/reports`, { headers: { 'Authorization': `Bearer ${token}` } });
            const reports = await response.json();
            reportsTableBody.innerHTML = '';
            reports.forEach(report => {
                const row = `
                    <tr>
                        <td><span class="status-${report.status}">${report.status}</span></td>
                        <td>${report.question.substring(0, 30)}...</td>
                        <td>${report.reported_by}</td>
                        <td>${report.error_type}</td>
                    </tr>
                `;
                reportsTableBody.innerHTML += row;
            });
        } catch (error) {
            console.error('Erro ao carregar reportes:', error);
            reportsTableBody.innerHTML = '<tr><td colspan="4">Erro ao carregar reportes.</td></tr>';
        }
    }

    async function deleteUser(userId) {
        if (!confirm(`Tem certeza que deseja apagar o usuário com ID ${userId}?`)) {
            return;
        }
        try {
            const response = await fetch(`${API_URL}/admin/users/${userId}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.message);
            
            alert(result.message);
            loadUsers(); // Recarrega a lista
        } catch (error) {
            alert(`Erro: ${error.message}`);
        }
    }
});