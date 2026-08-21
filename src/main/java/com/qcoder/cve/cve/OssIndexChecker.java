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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * 方式三(推荐)：Sonatype OSS Index 公共漏洞库 API。
 * POST https://ossindex.sonatype.org/api/v3/component-report
 * 免费、无需令牌、按 purl 批量查询（每次请求最多 128 个组件）。
 */
public class OssIndexChecker {

    public static final String ENDPOINT = "https://ossindex.sonatype.org/api/v3/component-report";
    private static final int CHUNK_SIZE = 100;

    /**
     * 批量查询，返回 purl -> 漏洞列表。
     */
    public static Map<String, List<VulnDetail>> query(List<String> purls, Consumer<String> log) throws IOException {
        Map<String, List<VulnDetail>> result = new HashMap<String, List<VulnDetail>>();
        if (purls.isEmpty()) return result;

        List<List<String>> chunks = chunk(purls, CHUNK_SIZE);
        for (int ci = 0; ci < chunks.size(); ci++) {
            List<String> chunk = chunks.get(ci);
            JsonArray coords = new JsonArray();
            for (String p : chunk) coords.add(p);
            JsonObject payload = new JsonObject();
            payload.add("coordinates", coords);

            Map<String, String> headers = new HashMap<String, String>();
            headers.put("Accept", "application/vnd.ossindex.component-report.v1+json");

            String resp = postWithRetry(payload.toString(), headers, log);
            JsonArray arr = (JsonArray) JsonParser.parseString(resp);
            for (JsonElement e : arr) {
                JsonObject o = e.getAsJsonObject();
                String coord = o.has("coordinates") ? o.get("coordinates").getAsString() : "";
                List<VulnDetail> vulns = new ArrayList<VulnDetail>();
                if (o.has("vulnerabilities") && o.get("vulnerabilities").isJsonArray()) {
                    for (JsonElement ve : o.getAsJsonArray("vulnerabilities")) {
                        JsonObject vo = ve.getAsJsonObject();
                        VulnDetail v = new VulnDetail();
                        v.cveId = getStr(vo, "id");
                        v.title = getStr(vo, "title");
                        v.description = getStr(vo, "description");
                        v.reference = getStr(vo, "reference");
                        if (v.cveId.startsWith("CVE-")) v.source = "cve";
                        if (vo.has("cvssScore")) {
                            v.cvssScore = vo.get("cvssScore").getAsDouble();
                            v.severityLabel = VulnDetail.labelOfScore(v.cvssScore);
                        }
                        if (vo.has("vulnerableVersions") && vo.get("vulnerableVersions").isJsonArray()) {
                            v.affectedVersions = join(vo.getAsJsonArray("vulnerableVersions"), "; ");
                        }
                        if (!v.cveId.isEmpty()) vulns.add(v);
                    }
                }
                if (!coord.isEmpty()) result.put(coord, vulns);
            }
            if (ci < chunks.size() - 1) {
                sleep(1200);
            }
        }
        return result;
    }

    private static String postWithRetry(String body, Map<String, String> headers, Consumer<String> log) throws IOException {
        int maxRetry = 4;
        for (int i = 0; i < maxRetry; i++) {
            try {
                return HttpUtil.postJson(ENDPOINT, body, headers, 60);
            } catch (IOException e) {
                if (e.getMessage() != null && e.getMessage().contains("429")) {
                    long wait = 8000L * (i + 1);
                    log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.ossRate", wait / 1000));
                    sleep(wait);
                } else {
                    throw e;
                }
            }
        }
        throw new IOException("OSS Index 持续限流，放弃该批次");
    }

    private static List<List<String>> chunk(List<String> list, int size) {
        List<List<String>> chunks = new ArrayList<List<String>>();
        for (int i = 0; i < list.size(); i += size) {
            chunks.add(list.subList(i, Math.min(i + size, list.size())));
        }
        return chunks;
    }

    private static String join(JsonArray arr, String sep) {
        StringBuilder sb = new StringBuilder();
        for (JsonElement e : arr) {
            if (sb.length() > 0) sb.append(sep);
            sb.append(e.getAsString());
        }
        return sb.toString();
    }

    private static String getStr(JsonObject o, String key) {
        JsonElement el = o.get(key);
        return (el == null || el.isJsonNull()) ? "" : el.getAsString();
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignored) {
        }
    }
}
