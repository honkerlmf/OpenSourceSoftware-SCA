package com.qcoder.cve.cve;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.qcoder.cve.i18n.I18n;
import com.qcoder.cve.model.Dependency;
import com.qcoder.cve.model.VulnDetail;
import com.qcoder.cve.util.HttpUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;

/**
 * 方式一(推荐)：OSV.dev 公共漏洞库 API（Google 维护，聚合 GitHub Advisory / NVD / 各生态官方源）。
 * POST https://api.osv.dev/v1/query  免费、无需令牌。
 * 返回 CVE / GHSA / OSV 编号、aliases(CVE别名)、CVSS 评分与修复版本范围。
 * 注：querybatch 端点仅返回摘要(id+modified)，因此逐组件查询以获取完整漏洞信息。
 */
public class OsvChecker {

    public static final String ENDPOINT = "https://api.osv.dev/v1/query";

    /**
     * 逐组件查询（4线程并行，含限流退避），返回 purl -> 漏洞列表。
     */
    public static Map<String, List<VulnDetail>> query(List<Dependency> deps, Consumer<String> log) throws IOException {
        Map<String, List<VulnDetail>> result = new HashMap<String, List<VulnDetail>>();
        if (deps.isEmpty()) return result;

        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Future<Map.Entry<String, List<VulnDetail>>>> futures = new ArrayList<Future<Map.Entry<String, List<VulnDetail>>>>();
            for (Dependency d : deps) {
                final Dependency dep = d;
                futures.add(pool.submit(new Callable<Map.Entry<String, List<VulnDetail>>>() {
                    @Override
                    public Map.Entry<String, List<VulnDetail>> call() throws Exception {
                        String purl = PurlBuilder.toPurl(dep);
                        if (purl == null) return null;
                        log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.osvOne", dep.display()));
                        JsonObject q = new JsonObject();
                        q.addProperty("version", dep.version);
                        JsonObject pkg = new JsonObject();
                        pkg.addProperty("name", dep.packageId);
                        pkg.addProperty("ecosystem", osvEcosystem(dep));
                        q.add("package", pkg);
                        Map<String, String> headers = new HashMap<String, String>();
                        headers.put("Content-Type", "application/json");
                        List<VulnDetail> vulns = new ArrayList<VulnDetail>();
                        String resp = postWithRetry(q.toString(), headers, log);
                        if (resp != null) {
                            JsonObject root = (JsonObject) JsonParser.parseString(resp);
                            if (root.has("vulns") && root.get("vulns").isJsonArray()) {
                                for (JsonElement ve : root.getAsJsonArray("vulns")) {
                                    VulnDetail v = parseVuln(ve.getAsJsonObject());
                                    if (v != null) vulns.add(v);
                                }
                            }
                        }
                        log.accept(I18n.tag("log.tag.query") + dep.display() + " → " + (vulns.isEmpty()
                                ? I18n.get("log.query.osvNone")
                                : I18n.get("log.query.osvFound", vulns.size(), I18n.severity(maxSeverityOf(vulns)), cveIdsOf(vulns))));
                        return new java.util.AbstractMap.SimpleEntry<String, List<VulnDetail>>(purl, vulns);
                    }
                }));
            }
            for (Future<Map.Entry<String, List<VulnDetail>>> f : futures) {
                Map.Entry<String, List<VulnDetail>> e = f.get();
                if (e != null) result.put(e.getKey(), e.getValue());
            }
        } catch (Exception e) {
            throw new IOException(I18n.get("log.query.osvQueryFail", e.getMessage()), e);
        } finally {
            pool.shutdownNow();
        }
        return result;
    }

    /**
     * 补充查询单个组件的官方修复版本列表（供非 OSV 通道查询后兜底填充修复建议）。
     * 仅解析 affected.ranges.events 中的 fixed 事件，失败返回空列表不影响主流程。
     */
    public static List<String> queryFixVersions(Dependency dep, Consumer<String> log) {
        List<String> fixes = new ArrayList<String>();
        try {
            String purl = PurlBuilder.toPurl(dep);
            if (purl == null) return fixes;
            JsonObject q = new JsonObject();
            q.addProperty("version", dep.version);
            JsonObject pkg = new JsonObject();
            pkg.addProperty("name", dep.packageId);
            pkg.addProperty("ecosystem", osvEcosystem(dep));
            q.add("package", pkg);
            Map<String, String> headers = new HashMap<String, String>();
            headers.put("Content-Type", "application/json");
            String resp = postWithRetry(q.toString(), headers, log);
            if (resp == null) return fixes;
            JsonObject root = (JsonObject) JsonParser.parseString(resp);
            if (!root.has("vulns") || !root.get("vulns").isJsonArray()) return fixes;
            Set<String> seen = new LinkedHashSet<String>();
            for (JsonElement ve : root.getAsJsonArray("vulns")) {
                JsonObject vo = ve.getAsJsonObject();
                if (!vo.has("affected") || !vo.get("affected").isJsonArray()) continue;
                for (JsonElement ae : vo.getAsJsonArray("affected")) {
                    JsonObject ao = ae.getAsJsonObject();
                    if (!ao.has("ranges") || !ao.get("ranges").isJsonArray()) continue;
                    for (JsonElement re : ao.getAsJsonArray("ranges")) {
                        JsonObject ro = re.getAsJsonObject();
                        if (!ro.has("events") || !ro.get("events").isJsonArray()) continue;
                        for (JsonElement ee : ro.getAsJsonArray("events")) {
                            JsonObject eo = ee.getAsJsonObject();
                            if (eo.has("fixed")) seen.add(eo.get("fixed").getAsString());
                        }
                    }
                }
            }
            fixes.addAll(seen);
        } catch (Exception e) {
            log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.osvFixFail", dep.display(), e.getMessage()));
        }
        return fixes;
    }

    private static VulnDetail parseVuln(JsonObject vo) {
        VulnDetail v = new VulnDetail();
        String id = getStr(vo, "id");
        if (id.isEmpty()) return null;
        v.title = getStr(vo, "summary");
        v.description = getStr(vo, "details");
        // CVE 编号优先取自身，其次取 aliases 中的 CVE
        v.cveId = id.startsWith("CVE-") ? id : "";
        if (vo.has("aliases") && vo.get("aliases").isJsonArray()) {
            for (JsonElement al : vo.getAsJsonArray("aliases")) {
                String alias = al.getAsString();
                if (alias.startsWith("CVE-")) {
                    if (v.cveId.isEmpty()) v.cveId = alias;
                    break;
                }
            }
        }
        if (v.cveId.isEmpty()) v.cveId = id; // 无 CVE 时保留 GHSA/OSV 编号
        v.reference = "https://osv.dev/vulnerability/" + id;
        v.source = id.startsWith("CVE-") ? "cve" : (id.startsWith("GHSA-") ? "github" : "osv");

        // CVSS 评分解析：1) 纯数字 2) 完整 v3 向量按公式计算 3) database_specific.severity 等级映射 4) affected 级评分回退
        if (vo.has("severity") && vo.get("severity").isJsonArray()) {
            JsonArray sevs = vo.getAsJsonArray("severity");
            if (sevs.size() > 0) {
                v.cvssScore = parseScore(sevs.get(0).getAsJsonObject().get("score").getAsString());
            }
        }
        if (v.cvssScore <= 0 && vo.has("database_specific") && vo.get("database_specific").isJsonObject()) {
            v.cvssScore = scoreOfSeverityWord(getStr(vo.getAsJsonObject("database_specific"), "severity"));
        }
        if (v.cvssScore <= 0 && vo.has("affected") && vo.get("affected").isJsonArray()) {
            for (JsonElement ae : vo.getAsJsonArray("affected")) {
                JsonObject ao = ae.getAsJsonObject();
                if (ao.has("severity") && ao.get("severity").isJsonArray()) {
                    for (JsonElement se : ao.getAsJsonArray("severity")) {
                        JsonObject so = se.getAsJsonObject();
                        String type = getStr(so, "type");
                        if ("CVSS_V3".equals(type) || "CVSS_V4".equals(type)) {
                            v.cvssScore = parseScore(getStr(so, "score"));
                            break;
                        }
                    }
                }
                if (v.cvssScore > 0) break;
            }
        }
        v.severityLabel = VulnDetail.labelOfScore(v.cvssScore);

        // 受影响的版本范围(含修复版本)
        if (vo.has("affected") && vo.get("affected").isJsonArray()) {
            StringBuilder range = new StringBuilder();
            for (JsonElement ae : vo.getAsJsonArray("affected")) {
                JsonObject ao = ae.getAsJsonObject();
                if (!ao.has("ranges") || !ao.get("ranges").isJsonArray()) continue;
                for (JsonElement re : ao.getAsJsonArray("ranges")) {
                    JsonObject ro = re.getAsJsonObject();
                    String rtype = getStr(ro, "type");
                    if (!"SEMVER".equals(rtype) && !"ECOSYSTEM".equals(rtype)) continue;
                    String introduced = "", fixed = "";
                    if (ro.has("events") && ro.get("events").isJsonArray()) {
                        for (JsonElement ee : ro.getAsJsonArray("events")) {
                            JsonObject eo = ee.getAsJsonObject();
                            if (eo.has("introduced")) introduced = eo.get("introduced").getAsString();
                            if (eo.has("fixed")) {
                                fixed = eo.get("fixed").getAsString();
                                if (v.fixVersion.isEmpty()) v.fixVersion = fixed;
                            }
                        }
                    }
                    String seg = introduced.isEmpty() ? "?" : introduced;
                    seg += " ~ " + (fixed.isEmpty() ? I18n.get("vuln.latest") : fixed + I18n.get("vuln.fixed"));
                    if (range.length() > 0) range.append("; ");
                    range.append(seg);
                }
            }
            v.affectedVersions = range.toString();
        }
        return v;
    }

    /** 解析 CVSS score 字段：支持纯数字与完整 v3 向量，解析失败返回 0 */
    private static double parseScore(String score) {
        if (score == null || score.trim().isEmpty()) return 0;
        try {
            return Double.parseDouble(score.trim());
        } catch (NumberFormatException ignored) {
        }
        double v3 = computeCvssV3(score.trim());
        return v3 > 0 ? v3 : 0;
    }

    /** 严重等级词汇 -> 代表性 CVSS 分数（0 表示无法识别） */
    private static double scoreOfSeverityWord(String word) {
        if (word == null) return 0;
        String w = word.trim().toUpperCase();
        if (w.contains("CRITICAL")) return 9.8;
        if (w.contains("HIGH")) return 8.0;
        if (w.contains("MODERATE") || w.contains("MEDIUM")) return 5.0;
        if (w.contains("LOW")) return 2.0;
        return 0;
    }

    /** 按 CVSS v3.1 官方公式计算 Base Score（仅依赖 AV/AC/PR/UI/S/C/I/A 指标） */
    private static double computeCvssV3(String vector) {
        Map<String, String> m = new HashMap<String, String>();
        for (String part : vector.split("/")) {
            int idx = part.indexOf(':');
            if (idx > 0) m.put(part.substring(0, idx), part.substring(idx + 1));
        }
        double av = val(m.get("AV"), "N", 0.85, "A", 0.62, "L", 0.55, "P", 0.2);
        double ac = val(m.get("AC"), "L", 0.77, "H", 0.44);
        boolean scopeChanged = "C".equals(m.get("S"));
        double pr = val(m.get("PR"), "N", 0.85);
        if ("L".equals(m.get("PR"))) pr = scopeChanged ? 0.68 : 0.62;
        else if ("H".equals(m.get("PR"))) pr = scopeChanged ? 0.5 : 0.27;
        double ui = val(m.get("UI"), "N", 0.85, "R", 0.62);
        double c = val(m.get("C"), "N", 0.0, "L", 0.22, "H", 0.56);
        double i = val(m.get("I"), "N", 0.0, "L", 0.22, "H", 0.56);
        double a = val(m.get("A"), "N", 0.0, "L", 0.22, "H", 0.56);
        if (av < 0 || ac < 0 || pr < 0 || ui < 0 || c < 0) return -1;
        double iss = 1 - (1 - c) * (1 - i) * (1 - a);
        double impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
        if (impact <= 0) return 0;
        double exploit = 8.22 * av * ac * pr * ui;
        double base = scopeChanged ? 1.08 * (impact + exploit) : impact + exploit;
        if (base > 10) base = 10;
        return Math.ceil(base * 10 - 1e-9) / 10;
    }

    /** 指标取值表：按 (键,值) 交替匹配，未知返回 -1 */
    private static double val(String key, Object... kv) {
        if (key == null) return -1;
        for (int i = 0; i < kv.length; i += 2) {
            if (key.equals(kv[i])) return (Double) kv[i + 1];
        }
        return -1;
    }

    private static String osvEcosystem(Dependency d) {
        switch (d.language) {
            case JAVA:
                return "Maven";
            case NODEJS:
                return "npm";
            case PYTHON:
                return "PyPI";
            case GO:
                return "Go";
            case RUST:
                return "crates.io";
            case PHP:
                return "Packagist";
            default:
                return "";
        }
    }

    /** 限流(429)时退避重试；其他错误直接抛出 */
    private static String postWithRetry(String body, Map<String, String> headers, Consumer<String> log) throws IOException {
        int maxRetry = 3;
        for (int i = 0; i < maxRetry; i++) {
            try {
                return HttpUtil.postJson(ENDPOINT, body, headers, 45);
            } catch (IOException e) {
                if (e.getMessage() != null && e.getMessage().contains("429")) {
                    long wait = 5000L * (i + 1);
                    log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.osvRate", wait / 1000));
                    try {
                        Thread.sleep(wait);
                    } catch (InterruptedException ignored) {
                    }
                } else {
                    throw e;
                }
            }
        }
        throw new IOException(I18n.get("log.query.osvQuit"));
    }

    private static String getStr(JsonObject o, String key) {
        JsonElement el = o.get(key);
        return (el == null || el.isJsonNull()) ? "" : el.getAsString();
    }

    /** 取漏洞列表中最高严重等级 */
    private static String maxSeverityOf(List<VulnDetail> vulns) {
        String max = "未知";
        for (VulnDetail v : vulns) {
            if ("严重".equals(v.severityLabel)) return "严重";
            if ("高危".equals(v.severityLabel)) max = "高危";
            else if ("中危".equals(v.severityLabel) && !"高危".equals(max)) max = "中危";
            else if ("低危".equals(v.severityLabel) && "未知".equals(max)) max = "低危";
        }
        return max;
    }

    /** CVE 编号列表（截断显示） */
    private static String cveIdsOf(List<VulnDetail> vulns) {
        StringBuilder sb = new StringBuilder();
        for (VulnDetail v : vulns) {
            if (sb.length() > 80) {
                sb.append(" 等共 ").append(vulns.size()).append(" 个");
                break;
            }
            if (sb.length() > 0) sb.append(", ");
            sb.append(v.cveId);
        }
        return sb.toString();
    }
}
