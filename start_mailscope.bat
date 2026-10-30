@echo off
setlocal
rem ---------------------------------------------------------------------------------------------
rem  MailScope launcher for Windows. Double-click this file.
rem  First run: creates a private Python environment (.venv) and installs the requirements.
rem  Every run:  starts MailScope and opens http://127.0.0.1:8501 in your browser.
rem  Everything stays on this computer. Close this window to stop MailScope.
rem ---------------------------------------------------------------------------------------------
cd /d "%~dp0"
title MailScope

if not exist "app.py" (
  echo.
  echo This file is not next to app.py. If you opened it from inside the zip file, close it,
  echo right-click the zip, choose "Extract All...", and double-click start_mailscope.bat in the
  echo extracted folder that contains app.py.
  echo.
  pause
  exit /b 1
)

rem --- 1. find Python 3.10 or newer --------------------------------------------------------------
set "PY="
py -3 --version >nul 2>&1 && set "PY=py -3"
if not defined PY python --version >nul 2>&1 && set "PY=python"
if not defined PY goto :nopython

%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if errorlevel 1 goto :oldpython

rem --- 2. private environment ----------------------------------------------------------------------
if not exist ".venv\Scripts\python.exe" (
  echo Creating a private Python environment, first run only...
  %PY% -m venv .venv
  if errorlevel 1 goto :venvfail
)

rem --- 3. requirements (first run only) ------------------------------------------------------------
if not exist ".venv\mailscope_installed.txt" (
  echo.
  echo Installing what MailScope needs. First run only. This needs internet and can take a few minutes...
  echo.
  ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
  if errorlevel 1 goto :installfail
  echo installed> ".venv\mailscope_installed.txt"
)

rem --- 4. quick self-check, then start -------------------------------------------------------------
echo.
".venv\Scripts\python.exe" -m mailscope.doctor
echo.
echo Starting MailScope. Your browser should open at http://127.0.0.1:8501
echo If it does not, open your browser and type that address yourself.
echo Leave this window open while you use MailScope. Close it to stop.
echo.
start "" /b ".venv\Scripts\python.exe" -c "import time, webbrowser; time.sleep(5); webbrowser.open('http://127.0.0.1:8501')"
".venv\Scripts\python.exe" -m streamlit run app.py
if errorlevel 1 goto :runfail
goto :end

:nopython
echo.
echo Python was not found on this computer.
echo   1. Open https://www.python.org/downloads/ and install Python 3.12 or newer.
echo   2. On the FIRST installer screen, tick "Add python.exe to PATH". Then click Install Now.
echo   3. Close this window and double-click start_mailscope.bat again.
echo.
pause
exit /b 1

:oldpython
echo.
echo Your Python is older than 3.10. Install a newer one from https://www.python.org/downloads/
echo (tick "Add python.exe to PATH"), then double-click start_mailscope.bat again.
echo.
pause
exit /b 1

:venvfail
echo.
echo Could not create the private environment. Copy ALL the text in this window and send it to Claude.
echo.
pause
exit /b 1

:installfail
echo.
echo Installing the requirements failed. Common causes: no internet, a company or school network
echo that blocks pip, or an antivirus program. Copy ALL the text in this window and send it to Claude.
echo.
%PY% -m mailscope.doctor
pause
exit /b 1

:runfail
echo.
echo MailScope stopped with an error. Copy ALL the text above and send it to Claude.
echo.
pause
exit /b 1

:end
endlocal
