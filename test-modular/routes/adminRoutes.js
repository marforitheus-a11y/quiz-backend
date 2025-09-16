// =================================================================
// ADMIN ROUTES - Rotas de administração completas
// =================================================================

const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const authenticateToken = require('../middlewares/auth');
const multer = require('multer');
const path = require('path');

// =================================================================
// MIDDLEWARE: Todas as rotas admin precisam de autenticação
// =================================================================
router.use(authenticateToken);
router.use(adminController.authorizeAdmin);

// =================================================================
// CONFIGURAÇÃO MULTER PARA UPLOADS
// =================================================================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = './uploads';
        if (!require('fs').existsSync(dir)) { 
            require('fs').mkdirSync(dir, { recursive: true }); 
        }
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        const safeName = `${Date.now()}-${require('uuid').v4()}${ext}`;
        cb(null, safeName);
    }
});

const upload = multer({ 
    storage: storage, 
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    fileFilter: (req, file, cb) => {
        const allowed = ['.pdf', '.png', '.jpg', '.jpeg', '.gif'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (!allowed.includes(ext)) {
            return cb(new Error('Tipo de arquivo não permitido'), false);
        }
        cb(null, true);
    }
});

// =================================================================
// GESTÃO DE USUÁRIOS
// =================================================================

// Listar usuários
router.get('/users', adminController.getUsers);

// Atualizar usuário
router.put('/users/:id', adminController.updateUser);

// Deletar usuário
router.delete('/users/:id', adminController.deleteUser);

// =================================================================
// BROADCAST E MENSAGENS
// =================================================================

// Enviar broadcast
router.post('/broadcast', upload.single('image'), adminController.broadcast);

// Definir mensagem global
router.post('/message', adminController.setMessage);

// Obter mensagem global
router.get('/message', adminController.getMessage);

// =================================================================
// SESSÕES E MONITORAMENTO
// =================================================================

// Sessões ativas
router.get('/sessions', adminController.getSessions);

// =================================================================
// RELATÓRIOS E ANÁLISES
// =================================================================

// Relatórios de erro
router.get('/reports', adminController.getReports);

// Dashboard com métricas
router.get('/dashboard/metrics', adminController.getDashboard);
router.get('/dashboard/simple', adminController.getDashboard);
router.get('/dashboard/test', (req, res) => {
    res.json({
        message: 'Dashboard test endpoint funcionando!',
        admin: req.user.username,
        timestamp: new Date().toISOString()
    });
});

// =================================================================
// GESTÃO DE QUESTÕES
// =================================================================

// Listar questões
router.get('/questions', adminController.getQuestions);

// Obter questão específica
router.get('/questions/:id', adminController.getQuestion);

// =================================================================
// FERRAMENTAS DE IA
// =================================================================

// Corrigir categorias das questões
router.post('/fix-categories', adminController.fixCategories);

// Correção avançada (placeholder para futuras funcionalidades)
router.post('/fix-categories-advanced', adminController.fixCategories);

// =================================================================
// ROTAS PÚBLICAS DE EMERGÊNCIA
// =================================================================

// Estas rotas são acessíveis sem admin para emergências
router.post('/public/fix-categories-emergency', (req, res, next) => {
    // Remove middleware de admin para esta rota específica
    req.skipAdminCheck = true;
    next();
}, adminController.fixCategories);

router.get('/public/diagnose-categories', (req, res) => {
    res.json({
        message: 'Diagnóstico de categorias disponível',
        timestamp: new Date().toISOString(),
        note: 'Esta é uma rota de emergência para diagnóstico'
    });
});

// =================================================================
// CRIAÇÃO DE DADOS DE TESTE
// =================================================================

// Criar relatórios de teste
router.post('/create-test-reports', async (req, res) => {
    try {
        const testReports = [
            {
                user_id: req.user.userId,
                question_id: 1,
                error_type: 'wrong_answer',
                description: 'Resposta correta está incorreta'
            },
            {
                user_id: req.user.userId,
                question_id: 2,
                error_type: 'typo',
                description: 'Erro de digitação na pergunta'
            }
        ];

        const db = require('../config/database');
        
        for (const report of testReports) {
            await db.query(`
                INSERT INTO error_reports (
                    user_id, question_id, error_type, description, 
                    status, created_at
                ) VALUES ($1, $2, $3, $4, 'pending', NOW())
            `, [report.user_id, report.question_id, report.error_type, report.description]);
        }

        res.json({
            message: 'Relatórios de teste criados',
            count: testReports.length
        });

    } catch (error) {
        console.error('❌ Erro ao criar relatórios de teste:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// =================================================================
// ROTAS DE DEBUG
// =================================================================
router.get('/debug', (req, res) => {
    res.json({
        message: 'Admin routes funcionando!',
        admin: req.user.username,
        timestamp: new Date().toISOString(),
        routes: [
            'GET /admin/users',
            'PUT /admin/users/:id',
            'DELETE /admin/users/:id',
            'POST /admin/broadcast',
            'POST /admin/message',
            'GET /admin/message',
            'GET /admin/sessions',
            'GET /admin/reports',
            'GET /admin/dashboard/metrics',
            'GET /admin/questions',
            'GET /admin/questions/:id',
            'POST /admin/fix-categories',
            'POST /admin/create-test-reports'
        ]
    });
});

module.exports = router;
