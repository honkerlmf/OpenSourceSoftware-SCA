package com.qcoder.cve.config;

/** 应用配置模型 */
public class AppConfig {

    public static final String METHOD_OSS_INDEX = "OSS_INDEX";
    public static final String METHOD_MVN_REPO = "MVN_REPO";
    public static final String METHOD_IQ_SERVER = "IQ_SERVER";
    public static final String METHOD_OSV = "OSV";

    /** 扫描模式：整个代码项目 */
    public static final String SCAN_MODE_PROJECT = "PROJECT";
    /** 扫描模式：单个 lib 文件夹 */
    public static final String SCAN_MODE_LIB_FOLDER = "LIB_FOLDER";
    /** 扫描模式：jar/war 包内 lib */
    public static final String SCAN_MODE_ARCHIVE = "ARCHIVE";

    public static class AiEndpoint {
        public String baseUrl = "";
        public String apiKey = "";
        public String model = "";
        public int timeoutSec = 60;

        public AiEndpoint() {
        }

        public AiEndpoint(String baseUrl, String apiKey, String model, int timeoutSec) {
            this.baseUrl = baseUrl;
            this.apiKey = apiKey;
            this.model = model;
            this.timeoutSec = timeoutSec;
        }
    }

    /** 外网 AI 模型 API (OpenAI 兼容) */
    public AiEndpoint externalAi = new AiEndpoint("https://api.openai.com/v1", "", "gpt-4o-mini", 60);
    /** 内网 AI 模型 API (OpenAI 兼容 / Ollama) */
    public AiEndpoint internalAi = new AiEndpoint("http://127.0.0.1:11434/v1", "", "qwen2.5:14b", 120);
    /** true=优先使用外网AI, false=使用内网AI */
    public boolean useExternalAi = true;

    /** 首选漏洞查询方式: OSV / OSS_INDEX / MVN_REPO / IQ_SERVER */
    public String queryMethod = METHOD_OSV;
    /** Sonatype IQ Server 地址(方式二)，如 http://127.0.0.1:8070 */
    public String iqServerUrl = "";
    /** Sonatype IQ Server 访问令牌 */
    public String iqToken = "";
    /** 首选方式失败时自动切换其他方式 */
    public boolean fallbackEnabled = true;
    /** 查询组件许可协议 */
    public boolean licenseEnabled = true;
    /** AI 辅助分析项目与依赖提取 */
    public boolean aiAnalyze = true;
    /** AI 生成漏洞修复建议 */
    public boolean aiFix = true;

    /** 依赖扫描模式: PROJECT / LIB_FOLDER / ARCHIVE */
    public String scanMode = SCAN_MODE_PROJECT;
    /** 界面语言: zh / en / fr / ja */
    public String language = "zh";
    public String lastFolder = "";
    public String lastOutput = "";
    /** 外部组件清单 Excel 路径（可选，填写后第二步直接读取该清单并弹出组件选择） */
    public String excelListFile = "";

    /** 补齐空值，防止旧配置文件缺字段导致 NPE */
    public void normalize() {
        if (externalAi == null) externalAi = new AiEndpoint("https://api.openai.com/v1", "", "gpt-4o-mini", 60);
        if (internalAi == null) internalAi = new AiEndpoint("http://127.0.0.1:11434/v1", "", "qwen2.5:14b", 120);
        if (externalAi.baseUrl == null) externalAi.baseUrl = "";
        if (externalAi.apiKey == null) externalAi.apiKey = "";
        if (externalAi.model == null) externalAi.model = "";
        if (internalAi.baseUrl == null) internalAi.baseUrl = "";
        if (internalAi.apiKey == null) internalAi.apiKey = "";
        if (internalAi.model == null) internalAi.model = "";
        if (externalAi.timeoutSec <= 0) externalAi.timeoutSec = 60;
        if (internalAi.timeoutSec <= 0) internalAi.timeoutSec = 120;
        if (queryMethod == null || queryMethod.length() == 0) queryMethod = METHOD_OSV;
        if (scanMode == null || scanMode.length() == 0) scanMode = SCAN_MODE_PROJECT;
        if (language == null || language.length() == 0) language = "zh";
        if (iqServerUrl == null) iqServerUrl = "";
        if (iqToken == null) iqToken = "";
        if (lastFolder == null) lastFolder = "";
        if (lastOutput == null) lastOutput = "";
        if (excelListFile == null) excelListFile = "";
    }
}
