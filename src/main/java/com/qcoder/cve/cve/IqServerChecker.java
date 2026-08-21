package com.qcoder.cve.cve;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.qcoder.cve.i18n.I18n;
import com.qcoder.cve.model.VulnDetail;
import com.qcoder.cve.util.HttpUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * 方式二：Sonatype IQ Server / Lifecycle REST API。
 * POST {server}/api/v2/components/details
 * 使用 Personal Access Token (sonatype_pat_...) 认证：优先 Bearer，401 时回退 Basic。
 * 返回 securityData.securityIssues(CVE) 与 licenseData.effectiveLicenses。
 */
public class IqServerChecker {

    public static class IqResult {
        public boolean success = false;
        public List<VulnDetail> vulns = new ArrayList<VulnDetail>();
        public String license = "";
        public String matchState = "";
        public String note = "";
    }

    /**
     * 批量查询（按 50 个一组），返回 purl -> 结果。
     */
    public static Map<String, IqResult> query(List<String> purls, String serverUrl, String token,
                                              Consumer<String> log) throws IOException {
        Map<String, IqResult> result = new HashMap<String, IqResult>();
        if (purls.isEmpty()) return result;
        String base = serverUrl == null ? "" : serverUrl.trim();
        while (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        String url = base + "/api/v2/components/details";

        for (int i = 0; i < purls.size(); i += 50) {
            List<String> chunk = purls.subList(i, Math.min(i + 50, purls.size()));
            JsonArray arr = new JsonArray();
            for (String p : chunk) {
                JsonObject o = new JsonObject();
                o.addProperty("packageUrl", p);
                arr.add(o);
            }
            JsonObject payload = new JsonObject();
            payload.add("components", arr);

            Map<String, String> headers = new HashMap<String, String>();
            headers.put("Content-Type", "application/json");
            String resp = postWithAuth(url, payload.toString(), token, headers, log);

            JsonObject root = (JsonObject) JsonParser.parseString(resp);
            JsonArray details = root.has("componentDetails") ? root.getAsJsonArray("componentDetails") : null;
            if (details != null) {
                for (JsonElement de : details) {
                    JsonObject item = de.getAsJsonObject();
                    String purl = "";
                    JsonObject component = item.has("component") ? item.getAsJsonObject("component") : null;
                    if (component != null && component.has("packageUrl")) {
                        purl = component.get("packageUrl").getAsString();
                    }
                    IqResult r = new IqResult();
                    r.matchState = item.has("matchState") ? item.get("matchState").getAsString() : "";
                    r.success = true;
                    // 安全漏洞
                    if (component != null && component.has("securityData")) {
                        JsonObject sd = component.getAsJsonObject("securityData");
                        if (sd.has("securityIssues") && sd.get("securityIssues").isJsonArray()) {
                            for (JsonElement se : sd.getAsJsonArray("securityIssues")) {
                                JsonObject so = se.getAsJsonObject();
                                String source = so.has("source") ? so.get("source").getAsString() : "";
                                String reference = so.has("reference") ? so.get("reference").getAsString() : "";
                                if (!"cve".equalsIgnoreCase(source)) continue; // 只记录 CVE
                                VulnDetail v = new VulnDetail();
                                v.cveId = reference;
                                v.source = source;
                                v.reference = so.has("url") ? so.get("url").getAsString() : "";
                                if (so.has("severity")) v.cvssScore = so.get("severity").getAsDouble();
                                v.threatCategory = so.has("threatCategory") ? so.get("threatCategory").getAsString() : "";
                                v.severityLabel = VulnDetail.labelOfCategory(v.threatCategory);
                                if (v.cvssScore > 0 && "未知".equals(v.severityLabel)) {
                                    v.severityLabel = VulnDetail.labelOfScore(v.cvssScore);
                                }
                                r.vulns.add(v);
                            }
                        }
                    }
                    // 许可协议
                    if (component != null && component.has("licenseData")) {
                        JsonObject ld = component.getAsJsonObject("licenseData");
                        if (ld.has("effectiveLicenses") && ld.get("effectiveLicenses").isJsonArray()) {
                            StringBuilder sb = new StringBuilder();
                            for (JsonElement le : ld.getAsJsonArray("effectiveLicenses")) {
                                JsonObject lo = le.getAsJsonObject();
                                String name = lo.has("licenseName") ? lo.get("licenseName").getAsString()
                                        : (lo.has("licenseId") ? lo.get("licenseId").getAsString() : "");
                                if (!name.isEmpty()) {
                                    if (sb.length() > 0) sb.append(", ");
                                    sb.append(name);
                                }
                            }
                            r.license = sb.toString();
                        }
                    }
                    if (!purl.isEmpty()) result.put(purl, r);
                }
            }
            if (i + 50 < purls.size()) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException ignored) {
                }
            }
        }
        return result;
    }

    private static String postWithAuth(String url, String body, String token, Map<String, String> headers,
                                       Consumer<String> log) throws IOException {
        try {
            headers.put("Authorization", "Bearer " + token);
            return HttpUtil.postJson(url, body, headers, 60);
        } catch (IOException e) {
            String msg = e.getMessage() == null ? "" : e.getMessage();
            if (msg.contains("401") || msg.contains("403")) {
                log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.iqAuth"));
                String basic = Base64.getEncoder().encodeToString((token + ":").getBytes("UTF-8"));
                headers.put("Authorization", "Basic " + basic);
                return HttpUtil.postJson(url, body, headers, 60);
            }
            throw e;
        }
    }
}
