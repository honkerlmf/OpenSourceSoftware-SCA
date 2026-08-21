package com.qcoder.cve.cve;

import com.qcoder.cve.model.Dependency;
import com.qcoder.cve.util.HttpUtil;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 方式一：mvnrepository.com 网页抓取。
 * URL 规则：https://mvnrepository.com/artifact/{groupId}/{artifactId}/{version}
 * 读取页面表格中的 License 行与 Vulnerabilities 行，并在漏洞详情页提取 CVE 编号。
 */
public class MvnRepoChecker {

    private static final Pattern CVE_PATTERN = Pattern.compile("CVE-\\d{4}-\\d+");
    private static final Pattern VULN_COUNT_PATTERN = Pattern.compile("(\\d+)\\s*(?:vulnerabilit|CVE)");

    public static class MvnRepoResult {
        public boolean success = false;
        public List<String> cveIds = new ArrayList<String>();
        public String license = "";
        public String vulnSummary = "";
        public String note = "";
    }

    public static MvnRepoResult query(Dependency d) {
        MvnRepoResult r = new MvnRepoResult();
        String url = PurlBuilder.toMvnRepoUrl(d);
        if (url == null) {
            r.note = "仅支持 Maven 组件";
            return r;
        }
        try {
            Document doc = Jsoup.connect(url)
                    .userAgent(HttpUtil.USER_AGENT)
                    .timeout(60000)
                    .followRedirects(true)
                    .get();

            String finalUrl = doc.location();
            if (!finalUrl.equals(url)) {
                r.note = "该精确版本页面不存在，已重定向至: " + finalUrl;
            }
            // 表格行: th=字段名, td=值
            for (Element tr : doc.select("table.grid tr")) {
                Element th = tr.selectFirst("th");
                Element td = tr.selectFirst("td");
                if (th == null || td == null) continue;
                String key = th.text().trim();
                String val = td.text().trim();
                if ("License".equalsIgnoreCase(key) && !val.isEmpty()) {
                    r.license = val;
                } else if ("Vulnerabilities".equalsIgnoreCase(key)) {
                    r.vulnSummary = val;
                }
            }
            // 页面中出现的所有 CVE
            Matcher m = CVE_PATTERN.matcher(doc.text());
            while (m.find()) r.cveIds.add(m.group());
            r.cveIds = dedup(r.cveIds);

            // 存在漏洞时再访问漏洞详情页补充 CVE 编号与数量
            if (r.vulnSummary.toLowerCase().contains("vulnerab")) {
                Matcher vm = VULN_COUNT_PATTERN.matcher(r.vulnSummary);
                String vulnPage = (finalUrl.endsWith("/") ? finalUrl : finalUrl + "/") + "vulnerabilities";
                try {
                    Document vdoc = Jsoup.connect(vulnPage)
                            .userAgent(HttpUtil.USER_AGENT)
                            .timeout(60000)
                            .followRedirects(true)
                            .get();
                    Matcher vm2 = CVE_PATTERN.matcher(vdoc.text());
                    List<String> pageCves = new ArrayList<String>();
                    while (vm2.find()) pageCves.add(vm2.group());
                    if (!pageCves.isEmpty()) r.cveIds = dedup(pageCves);
                } catch (Exception ignored) {
                    // 漏洞详情页抓取失败不影响主结果
                }
            }
            r.success = true;
            return r;
        } catch (Exception e) {
            r.note = "抓取失败: " + e.getMessage();
            return r;
        }
    }

    private static List<String> dedup(List<String> list) {
        Set<String> set = new LinkedHashSet<String>(list);
        return new ArrayList<String>(set);
    }
}
