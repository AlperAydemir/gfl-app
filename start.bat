@echo off
title GFL Uygulaması - Başlatılıyor...
echo Sanal ortam etkinleştiriliyor...

REM Eğer sanal ortam varsa onu etkinleştir
if exist venv\Scripts\activate (
    call venv\Scripts\activate
) else (
    echo [UYARI] Sanal ortam bulunamadı! (venv klasörü yok)
)

echo Flask uygulaması başlatılıyor...
set FLASK_APP=app.py
set FLASK_ENV=development
flask run

pause
