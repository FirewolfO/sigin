@echo off
setlocal
set "PROJECT_DIR=%~dp0"
set "MAVEN_VERSION=3.9.11"
set "MAVEN_HOME=%PROJECT_DIR%.mvn\wrapper\apache-maven-%MAVEN_VERSION%"
set "ARCHIVE=%PROJECT_DIR%.mvn\wrapper\apache-maven-%MAVEN_VERSION%-bin.zip"

if not exist "%MAVEN_HOME%\bin\mvn.cmd" (
  if not exist "%ARCHIVE%" powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing 'https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/%MAVEN_VERSION%/apache-maven-%MAVEN_VERSION%-bin.zip' -OutFile '%ARCHIVE%'"
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -Force '%ARCHIVE%' '%PROJECT_DIR%.mvn\wrapper'"
)

call "%MAVEN_HOME%\bin\mvn.cmd" %*
endlocal
