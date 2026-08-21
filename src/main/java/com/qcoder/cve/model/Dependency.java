package com.qcoder.cve.model;

import java.util.ArrayList;
import java.util.List;

/**
 * 依赖组件模型。
 * packageId 为组件唯一标识：Java 为 groupId:artifactId，其他语言为包名。
 */
public class Dependency {

    public enum Language {
        JAVA("Java"), NODEJS("Node.js"), PYTHON("Python"), GO("Go"), RUST("Rust"), PHP("PHP"), UNKNOWN("未知");

        private final String label;

        Language(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }

        public static Language parse(String s) {
            if (s == null) return UNKNOWN;
            String t = s.trim().toLowerCase();
            if (t.contains("java") || t.contains("maven")) return JAVA;
            if (t.contains("node") || t.contains("npm") || t.contains("javascript") || t.contains("js")) return NODEJS;
            if (t.contains("python") || t.contains("pip") || t.contains("pypi")) return PYTHON;
            if (t.contains("go") || t.contains("golang")) return GO;
            if (t.contains("rust") || t.contains("cargo")) return RUST;
            if (t.contains("php") || t.contains("composer")) return PHP;
            return UNKNOWN;
        }
    }

    /** 组件唯一标识：groupId:artifactId 或包名 */
    public String packageId = "";
    /** Maven groupId */
    public String groupId = "";
    /** Maven artifactId / 包名 */
    public String artifactId = "";
    /** 代码内使用的版本 */
    public String version = "";
    /** 版本为变量/未锁定 */
    public boolean versionVariable = false;
    /** 版本未知/未锁定（无真实版本，用于逻辑判断，不依赖显示文本） */
    public boolean versionUnknown = false;
    /** 组件代码语言 */
    public Language language = Language.UNKNOWN;
    /** 引入方式，如 Maven依赖 / 本地Jar包 / npm依赖 / pip依赖 */
    public String introduceType = "";
    /** 来源配置文件路径 */
    public String sourceFile = "";
    /** 所属项目(配置文件所在目录相对扫描根目录) */
    public String projectName = "";
    /** 作用域 */
    public String scope = "";

    // ---------- 漏洞查询结果 ----------
    public boolean vulnChecked = false;
    /** 查询状态：成功 / 失败原因 */
    public String queryStatus = "";
    /** 查询被跳过（无有效版本等），用于逻辑判断 */
    public boolean querySkipped = false;
    /** 实际使用的查询方式 */
    public String queryMethod = "";
    /** 漏洞(CVE)列表 */
    public List<VulnDetail> cveList = new ArrayList<VulnDetail>();
    /** 组件许可协议 */
    public String license = "";
    /** AI 修复建议 */
    public String aiFixSuggestion = "";
    /** 官方 API 修复建议（漏洞库返回的修复版本，AI 不可用时兜底） */
    public String apiFixSuggestion = "";
    /** 修复建议获取日期（接口读取日期，格式 yyyy-MM-dd） */
    public String fixSuggestionDate = "";

    public boolean isVulnChecked() {
        return vulnChecked;
    }

    public boolean isHasVuln() {
        return vulnChecked && !cveList.isEmpty();
    }

    public String getMaxSeverityLabel() {
        String max = "";
        for (VulnDetail v : cveList) {
            if (v.severityLabel != null && !v.severityLabel.isEmpty()) {
                if ("严重".equals(v.severityLabel)) return "严重";
                if ("高危".equals(v.severityLabel)) max = "高危";
                else if ("中危".equals(v.severityLabel) && !"高危".equals(max) && !"严重".equals(max)) max = "中危";
                else if ("低危".equals(v.severityLabel) && max.isEmpty()) max = "低危";
            }
        }
        return max.isEmpty() ? "未知" : max;
    }

    public String getCveIdsText() {
        StringBuilder sb = new StringBuilder();
        for (VulnDetail v : cveList) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(v.cveId);
        }
        return sb.toString();
    }

    /** 组件显示名：packageId@version */
    public String display() {
        return packageId + "@" + version;
    }
}
