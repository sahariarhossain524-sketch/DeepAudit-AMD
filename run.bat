@echo off
title AegisCode AMD - Autonomous Code Auditor
echo ========================================================
echo  Starting AegisCode AMD Server on http://127.0.0.1:8000
echo  Powered by AMD Token Factory and Google Gemma-4-31B-IT
echo ========================================================
start http://127.0.0.1:8000
python server.py
pause
