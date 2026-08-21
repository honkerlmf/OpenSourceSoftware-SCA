package com.qcoder.cve.model;

/** 单个 CVE 漏洞明细 */
public class VulnDetail {

    /** CVE 编号，如 CVE-2021-44228 */
    public String cveId = "";
    /** 漏洞标题 */
    public String title = "";
    /** 漏洞描述 */
    public String description = "";
    /** CVSS 评分(0-10) */
    public double cvssScore = 0;
    /** 严重等级：严重/高危/中危/低危/未知 */
    public String severityLabel = "未知";
    /** 威胁分类(来自IQ) */
    public String threatCategory = "";
    /** 参考链接 */
    public String reference = "";
    /** 漏洞来源：cve/osvdb 等 */
    public String source = "";
    /** 受影响的版本范围 */
    public String affectedVersions = "";
    /** 官方修复版本（来自 OSV 等漏洞库的 fixed 事件，可为空） */
    public String fixVersion = "";

    public static String labelOfScore(double score) {
        if (score >= 9.0) return "严重";
        if (score >= 7.0) return "高危";
        if (score >= 4.0) return "中危";
        if (score > 0) return "低危";
        return "未知";
    }

    public static String labelOfCategory(String category) {
        if (category == null) return "未知";
        String c = category.trim().toLowerCase();
        if (c.contains("critical")) return "严重";
        if (c.contains("severe") || c.contains("high")) return "高危";
        if (c.contains("moderate") || c.contains("medium")) return "中危";
        if (c.contains("low")) return "低危";
        return "未知";
    }
}
