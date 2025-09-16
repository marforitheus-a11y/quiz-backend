@echo off
echo.
echo ============================================
echo  REINICIANDO SERVIDOR COM TEMAS CORRETOS
echo ============================================
echo.

echo Parando processos Node.js na porta 4000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :4000') do (
    echo Finalizando processo %%a
    taskkill /PID %%a /F >nul 2>&1
)

echo Aguardando 2 segundos...
timeout /t 2 /nobreak >nul

echo.
echo Iniciando servidor com temas corretos...
echo Frontend: http://localhost:8080
echo Backend:  http://localhost:4000
echo.

node app-simple.js
