@echo off
chcp 65001 >nul
cd /d %~dp0
echo ============================================
echo  AI 依赖组件安全漏洞(CVE)审计工具
echo ============================================
where java >nul 2>nul
if errorlevel 1 (
    echo [错误] 未检测到 Java 运行时，请先安装 JDK 1.8+
    pause
    exit /b 1
)
if not exist target\cve-dependency-scanner.jar (
    echo [提示] 未找到可执行 jar，正在执行 Maven 构建...
    call mvn package -q -DskipTests
    if errorlevel 1 (
        echo [错误] 构建失败，请确认已安装 Maven 3.6+
        pause
        exit /b 1
    )
)
echo [启动] 正在启动应用...
java -jar target\cve-dependency-scanner.jar
if errorlevel 1 pause
