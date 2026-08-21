package com.qcoder.cve.ai;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.qcoder.cve.model.Dependency;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * AI 分析服务：项目分析、依赖补充提取、漏洞修复建议。
 */
public class AiService {

    private final AiClient client;

    public AiService(AiClient client) {
        this.client = client;
    }

    public AiClient getClient() {
        return client;
    }

    /** 项目分析结果 */
    public static class AnalysisResult {
        public String analysis = "";
        public List<Dependency> extraDependencies = new ArrayList<Dependency>();
    }

    /** 修复建议 */
    public static class FixSuggestion {
        public String packageId = "";
        public String recommendedVersion = "";
        public String note = "";
    }

    /**
     * AI 分析项目：输出项目总体分析报告 + 补充规则解析遗漏的依赖组件。
     */
    public AnalysisResult analyzeProject(File root, List<String> configFiles, List<Dependency> deps) {
        AnalysisResult result = new AnalysisResult();
        if (client == null || !client.isConfigured()) {
            return result;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("项目根目录: ").append(root.getAbsolutePath()).append("\n\n");
        sb.append("检测到的依赖配置文件(").append(configFiles.size()).append("个):\n");
        for (String f : configFiles) {
            sb.append("- ").append(f).append("\n");
        }
        sb.append("\n已解析的依赖组件清单(").append(deps.size()).append("个):\n");
        int i = 1;
        for (Dependency d : deps) {
            sb.append(i++).append(". ").append(d.packageId)
                    .append(" @ ").append(d.version)
                    .append(" [").append(d.language.getLabel()).append("] ")
                    .append("[").append(d.introduceType).append("] ")
                    .append("来源: ").append(d.sourceFile).append("\n");
        }
        sb.append("\n请重点核对：1) 锁文件(package-lock.json/yarn.lock/poetry.lock)中未被解析的精确版本；")
                .append("2) pom.xml 的 dependencyManagement 与多模块子项目；")
                .append("3) requirements.txt 之外的 Python 依赖；")
                .append("4) Dockerfile 基础镜像中的组件、shell 脚本中下载的二进制依赖等。");

        String system = "你是一名资深软件供应链安全审计专家与软件架构师。请根据给定的项目文件清单与已解析的依赖组件清单，"
                + "输出项目的总体分析报告（中文），并识别规则解析可能遗漏的第三方依赖组件。"
                + "只输出一个 JSON 对象，不要输出任何其他内容。JSON 格式："
                + "{\"analysis\":\"项目分析报告(markdown格式，包含：项目类型与架构概述、技术栈、依赖配置说明、主要安全风险点、改进建议)\","
                + "\"extraDependencies\":[{\"packageId\":\"groupId:artifactId或包名\",\"version\":\"版本号\","
                + "\"language\":\"JAVA|NODEJS|PYTHON|GO|RUST|PHP\",\"introduceType\":\"引入方式说明\",\"sourceFile\":\"配置文件路径\"}]}";
        try {
            String content = client.chat(system, sb.toString());
            JsonObject json = parseJsonObject(content);
            if (json != null) {
                if (json.has("analysis")) result.analysis = json.get("analysis").getAsString();
                if (json.has("extraDependencies") && json.get("extraDependencies").isJsonArray()) {
                    JsonArray arr = json.getAsJsonArray("extraDependencies");
                    for (JsonElement e : arr) {
                        try {
                            JsonObject o = e.getAsJsonObject();
                            Dependency d = new Dependency();
                            d.packageId = getStr(o, "packageId");
                            d.artifactId = d.packageId.contains(":") ? d.packageId.substring(d.packageId.indexOf(':') + 1) : d.packageId;
                            d.groupId = d.packageId.contains(":") ? d.packageId.substring(0, d.packageId.indexOf(':')) : "";
                            d.version = getStr(o, "version");
                            d.language = Dependency.Language.parse(getStr(o, "language"));
                            d.introduceType = getStr(o, "introduceType");
                            d.sourceFile = getStr(o, "sourceFile");
                            d.versionVariable = d.version.isEmpty();
                            if (!d.packageId.isEmpty() && !d.version.isEmpty()) {
                                result.extraDependencies.add(d);
                            }
                        } catch (Exception ex) {
                            // 跳过单条格式错误的补充依赖
                        }
                    }
                }
            }
        } catch (Exception e) {
            result.analysis = "AI 项目分析调用失败: " + e.getMessage();
        }
        return result;
    }

    /**
     * AI 为存在漏洞的组件生成修复建议。
     */
    public List<FixSuggestion> suggestFixes(List<Dependency> vulnDeps) {
        List<FixSuggestion> fixes = new ArrayList<FixSuggestion>();
        if (client == null || !client.isConfigured() || vulnDeps.isEmpty()) {
            return fixes;
        }
        StringBuilder sb = new StringBuilder("存在CVE漏洞的组件清单:\n");
        for (Dependency d : vulnDeps) {
            sb.append("- ").append(d.packageId).append("@").append(d.version)
                    .append(" [").append(d.language.getLabel()).append("] 漏洞: ");
            for (int i = 0; i < d.cveList.size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append(d.cveList.get(i).cveId).append("(").append(d.cveList.get(i).severityLabel).append(")");
            }
            sb.append("\n");
        }
        String system = "你是软件供应链安全专家。请为上述每个存在漏洞的组件推荐可升级到的安全版本并给出简要修复建议。"
                + "只输出一个 JSON 数组，不要输出任何其他内容。格式："
                + "[{\"packageId\":\"组件标识\",\"recommendedVersion\":\"安全版本\",\"note\":\"简要修复建议\"}]。"
                + "要求：推荐版本需尽量小的大版本升级（兼容性优先）；若组件已是最新版本仍存在漏洞，recommendedVersion填\"暂无\"并在note中说明应关注官方补丁或替换组件。";
        try {
            String content = client.chat(system, sb.toString());
            JsonElement el = extractJsonElement(content);
            if (el != null && el.isJsonArray()) {
                for (JsonElement e : el.getAsJsonArray()) {
                    try {
                        JsonObject o = e.getAsJsonObject();
                        FixSuggestion f = new FixSuggestion();
                        f.packageId = getStr(o, "packageId");
                        f.recommendedVersion = getStr(o, "recommendedVersion");
                        f.note = getStr(o, "note");
                        if (!f.packageId.isEmpty()) fixes.add(f);
                    } catch (Exception ex) {
                        // 跳过单条格式错误
                    }
                }
            }
        } catch (Exception e) {
            // AI 失败时返回空列表，由调用方记录日志
        }
        return fixes;
    }

    private static String getStr(JsonObject o, String key) {
        JsonElement el = o.get(key);
        return (el == null || el.isJsonNull()) ? "" : el.getAsString();
    }

    /** 从 AI 回复中提取 JSON 对象（容忍 ```json 代码块包裹） */
    public static JsonObject parseJsonObject(String content) {
        JsonElement el = extractJsonElement(content);
        return (el != null && el.isJsonObject()) ? el.getAsJsonObject() : null;
    }

    public static JsonElement extractJsonElement(String content) {
        if (content == null) return null;
        String s = content.trim();
        int start = s.indexOf('{');
        int end = s.lastIndexOf('}');
        if (start == -1) {
            start = s.indexOf('[');
            end = s.lastIndexOf(']');
        }
        if (start == -1 || end <= start) return null;
        s = s.substring(start, end + 1);
        try {
            return JsonParser.parseString(s);
        } catch (Exception e) {
            return null;
        }
    }
}
