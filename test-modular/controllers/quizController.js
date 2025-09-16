// controllers/quizController.js - Controlador do quiz
const db = require('../config/database');

class QuizController {
  // Buscar temas
  static async getThemes(req, res) {
    try {
      const result = await db.query(`
        SELECT t.id, t.name, t.description, c.name as category_name 
        FROM themes t 
        LEFT JOIN categories c ON t.category_id = c.id 
        ORDER BY t.name
      `);

      res.json({
        status: 'success',
        themes: result.rows
      });

    } catch (error) {
      console.error('Erro ao buscar temas:', error);
      res.status(500).json({
        status: 'error',
        message: 'Erro ao buscar temas'
      });
    }
  }

  // Buscar questões
  static async getQuestions(req, res) {
    try {
      const { themeIds, limit = 10 } = req.query;
      
      let query = `
        SELECT q.id, q.question_text, q.answer_a, q.answer_b, q.answer_c, q.answer_d, 
               q.correct_answer, q.difficulty, t.name as theme_name
        FROM questions q
        JOIN themes t ON q.theme_id = t.id
      `;
      
      let params = [];
      
      if (themeIds) {
        const themeIdArray = themeIds.split(',').map(id => parseInt(id)).filter(id => !isNaN(id));
        if (themeIdArray.length > 0) {
          query += ` WHERE q.theme_id = ANY($1)`;
          params.push(themeIdArray);
        }
      }
      
      query += ` ORDER BY RANDOM() LIMIT $${params.length + 1}`;
      params.push(parseInt(limit));

      const result = await db.query(query, params);

      res.json({
        status: 'success',
        questions: result.rows
      });

    } catch (error) {
      console.error('Erro ao buscar questões:', error);
      res.status(500).json({
        status: 'error',
        message: 'Erro ao buscar questões'
      });
    }
  }

  // Estatísticas do usuário
  static async getUserStats(req, res) {
    try {
      const userId = req.user.id;

      const result = await db.query(`
        SELECT 
          COUNT(*) as total_quizzes,
          AVG(score) as average_score,
          MAX(score) as best_score,
          MIN(score) as worst_score
        FROM quiz_results 
        WHERE user_id = $1
      `, [userId]);

      res.json({
        status: 'success',
        stats: result.rows[0]
      });

    } catch (error) {
      console.error('Erro ao buscar estatísticas:', error);
      res.status(500).json({
        status: 'error',
        message: 'Erro ao buscar estatísticas'
      });
    }
  }

  // Submeter quiz
  static async submitQuiz(req, res) {
    try {
      const userId = req.user.id;
      const { answers, themeIds, totalQuestions } = req.body;

      if (!answers || !Array.isArray(answers)) {
        return res.status(400).json({
          status: 'error',
          message: 'Respostas são obrigatórias'
        });
      }

      let correctAnswers = 0;
      
      // Verificar respostas
      for (const answer of answers) {
        const questionResult = await db.query(
          'SELECT correct_answer FROM questions WHERE id = $1',
          [answer.questionId]
        );
        
        if (questionResult.rows.length > 0 && 
            questionResult.rows[0].correct_answer === answer.selectedAnswer) {
          correctAnswers++;
        }
      }

      const score = (correctAnswers / answers.length) * 100;

      // Salvar resultado
      const result = await db.query(`
        INSERT INTO quiz_results (user_id, score, total_questions, correct_answers, theme_ids)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, score, created_at
      `, [userId, score, answers.length, correctAnswers, themeIds || null]);

      res.json({
        status: 'success',
        message: 'Quiz submetido com sucesso!',
        result: {
          id: result.rows[0].id,
          score: score,
          correctAnswers: correctAnswers,
          totalQuestions: answers.length,
          percentage: Math.round(score),
          submittedAt: result.rows[0].created_at
        }
      });

    } catch (error) {
      console.error('Erro ao submeter quiz:', error);
      res.status(500).json({
        status: 'error',
        message: 'Erro ao submeter quiz'
      });
    }
  }
}

module.exports = QuizController;
