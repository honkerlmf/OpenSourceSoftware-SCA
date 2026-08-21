package com.qcoder.cve.cve;

import com.qcoder.cve.config.AppConfig;
import com.qcoder.cve.i18n.I18n;
import com.qcoder.cve.model.Dependency;
import com.qcoder.cve.model.VulnDetail;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 漏洞查询编排服务。
 * 按用户选择的查询方式批量查询，失败时自动降级到其他方式，
 * 最后补充查询组件许可协议。
 */
public class CveQueryService {

    private final AppConfig cfg;

    public CveQueryService(AppConfig cfg) {
        this.cfg = cfg;
    }

    /** 对全部依赖组件执行漏洞查询 + 许可协议查询 */
    public void queryAll(List<Dependency> deps, Consumer<String> log) {
        long t0 = System.currentTimeMillis();
        List<Dependency> remaining = new ArrayList<Dependency>(deps);

        // 首选查询方式
        int ok = doQuery(remaining, cfg.queryMethod, log);
        log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.first", methodName(cfg.queryMethod), ok));
        removeChecked(remaining);

        // 自动降级
        if (cfg.fallbackEnabled && !remaining.isEmpty()) {
            String[] fallbacks = {AppConfig.METHOD_OSV, AppConfig.METHOD_OSS_INDEX, AppConfig.METHOD_MVN_REPO, AppConfig.METHOD_IQ_SERVER};
            for (String fb : fallbacks) {
                if (fb.equals(cfg.queryMethod)) continue;
                if (remaining.isEmpty()) break;
                ok = doQuery(remaining, fb, log);
                if (ok > 0) log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.fallback", methodName(fb), ok));
                removeChecked(remaining);
            }
        }

        // 仍未查询的（无有效版本 / 所有方式均失败）
        for (Dependency d : remaining) {
            if (!d.vulnChecked) {
                d.vulnChecked = true;
                d.queryStatus = (PurlBuilder.toPurl(d) == null)
                        ? "无有效版本(未锁定/变量)，跳过漏洞查询"
                        : "所有查询方式均未成功";
                d.queryMethod = "-";
                log.accept(I18n.tag("log.tag.query") + d.display() + " → " + I18n.localizeStatus(d.queryStatus));
            }
        }

        // 许可协议查询
        if (cfg.licenseEnabled) {
            int licCount = 0;
            for (Dependency d : deps) {
                if (d.license != null && !d.license.isEmpty()) continue;
                String mvnLicense = "";
                if (AppConfig.METHOD_MVN_REPO.equals(d.queryMethod) && d.language == Dependency.Language.JAVA) {
                    // 优先使用 mvnrepository 页面抓到的许可
                }
                d.license = LicenseResolver.resolve(d, mvnLicense);
                if (!"未知".equals(d.license) && !"未知(未声明)".equals(d.license)) licCount++;
                log.accept(I18n.tag("log.tag.lic") + d.display() + " → " + I18n.localizeValue(d.license));
                sleep(300);
            }
            log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.licDone", licCount));
        }

        // 官方修复版本建议汇总（AI 不可用时充当修复建议兜底）
        summarizeFixSuggestions(deps, log);

        // 汇总
        int vulnCount = 0, critical = 0, high = 0;
        for (Dependency d : deps) {
            if (d.isHasVuln()) {
                vulnCount++;
                if ("严重".equals(d.getMaxSeverityLabel())) critical++;
                else if ("高危".equals(d.getMaxSeverityLabel())) high++;
            }
        }
        long cost = (System.currentTimeMillis() - t0) / 1000;
        log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.done", cost, deps.size(), vulnCount, critical, high,
                deps.size() - vulnCount - countSkipped(deps)));
    }

    private int countSkipped(List<Dependency> deps) {
        int n = 0;
        for (Dependency d : deps) {
            if (d.vulnChecked && d.cveList.isEmpty() && d.queryStatus.contains("跳过")) n++;
        }
        return n;
    }

    /**
     * 用指定方式查询，返回成功标记的组件数。
     */
    private int doQuery(List<Dependency> deps, String method, Consumer<String> log) {
        int checked = 0;
        try {
            if (AppConfig.METHOD_OSS_INDEX.equals(method)) {
                checked = queryByOssIndex(deps, log);
            } else if (AppConfig.METHOD_MVN_REPO.equals(method)) {
                checked = queryByMvnRepo(deps, log);
            } else if (AppConfig.METHOD_IQ_SERVER.equals(method)) {
                checked = queryByIqServer(deps, log);
            } else if (AppConfig.METHOD_OSV.equals(method)) {
                checked = queryByOsv(deps, log);
            }
        } catch (Exception e) {
            log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.methodFail", methodName(method), e.getMessage()));
        }
        return checked;
    }

    private int queryByOssIndex(List<Dependency> deps, Consumer<String> log) throws IOException {
        List<Dependency> targets = new ArrayList<Dependency>();
        List<String> purls = new ArrayList<String>();
        for (Dependency d : deps) {
            if (d.vulnChecked) continue;
            String purl = PurlBuilder.toPurl(d);
            if (purl == null) {
                d.vulnChecked = true;
                d.queryStatus = "无有效版本(未锁定/变量)，跳过漏洞查询";
                d.queryMethod = "-";
                continue;
            }
            targets.add(d);
            purls.add(purl);
        }
        if (targets.isEmpty()) return 0;
        log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.ossBatch", targets.size()));
        Map<String, List<VulnDetail>> result = OssIndexChecker.query(purls, log);
        int ok = 0;
        for (int i = 0; i < targets.size(); i++) {
            Dependency d = targets.get(i);
            String purl = purls.get(i);
            List<VulnDetail> vulns = result.get(purl);
            if (vulns != null || result.containsKey(purl)) {
                if (vulns == null) vulns = new ArrayList<VulnDetail>();
                mergeVulns(d, vulns);
                d.vulnChecked = true;
                d.queryStatus = "成功";
                d.queryMethod = "OSS Index";
                ok++;
                logDepResult(d, "OSS Index", log);
            } else {
                d.queryStatus = "OSS Index 未返回该组件结果";
            }
        }
        return ok;
    }

    private int queryByOsv(List<Dependency> deps, Consumer<String> log) throws IOException {
        List<Dependency> targets = new ArrayList<Dependency>();
        for (Dependency d : deps) {
            if (d.vulnChecked) continue;
            if (PurlBuilder.toPurl(d) == null) continue; // 由最终兜底逻辑处理
            targets.add(d);
        }
        if (targets.isEmpty()) return 0;
        log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.osvBatch", targets.size()));
        Map<String, List<VulnDetail>> result = OsvChecker.query(targets, log);
        int ok = 0;
        for (Dependency d : targets) {
            String purl = PurlBuilder.toPurl(d);
            List<VulnDetail> vulns = result.get(purl);
            if (vulns != null || result.containsKey(purl)) {
                if (vulns == null) vulns = new ArrayList<VulnDetail>();
                mergeVulns(d, vulns);
                d.vulnChecked = true;
                d.queryStatus = "成功";
                d.queryMethod = "OSV.dev";
                ok++;
            } else {
                d.queryStatus = "OSV 未返回该组件结果";
            }
        }
        return ok;
    }

    private int queryByMvnRepo(List<Dependency> deps, Consumer<String> log) {
        int ok = 0;
        for (Dependency d : deps) {
            if (d.vulnChecked) continue;
            if (d.language != Dependency.Language.JAVA) {
                continue; // 非Java组件留给其他方式查询
            }
            log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.mvn", d.display()));
            MvnRepoChecker.MvnRepoResult r = MvnRepoChecker.query(d);
            if (r.success) {
                List<VulnDetail> vulns = new ArrayList<VulnDetail>();
                for (String cve : r.cveIds) {
                    VulnDetail v = new VulnDetail();
                    v.cveId = cve;
                    v.source = "cve";
                    v.severityLabel = "未知";
                    v.reference = "https://nvd.nist.gov/vuln/detail/" + cve;
                    vulns.add(v);
                }
                mergeVulns(d, vulns);
                d.license = r.license;
                d.vulnChecked = true;
                d.queryStatus = r.note.isEmpty() ? "成功" : "成功(" + r.note + ")";
                d.queryMethod = "mvnrepository";
                ok++;
                logDepResult(d, "mvnrepository", log);
            } else {
                d.queryStatus = "mvnrepository查询失败: " + r.note;
                log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.mvnFail", d.display(), "mvnrepository", r.note));
            }
            sleep(500);
        }
        return ok;
    }

    private int queryByIqServer(List<Dependency> deps, Consumer<String> log) throws IOException {
        if (cfg.iqServerUrl == null || cfg.iqServerUrl.trim().isEmpty()) {
            for (Dependency d : deps) {
                if (!d.vulnChecked) {
                    d.vulnChecked = true;
                    d.queryStatus = "未配置 IQ Server 服务器地址";
                    d.queryMethod = "IQ Server";
                }
            }
            return deps.size();
        }
        List<Dependency> targets = new ArrayList<Dependency>();
        List<String> purls = new ArrayList<String>();
        for (Dependency d : deps) {
            if (d.vulnChecked) continue;
            String purl = PurlBuilder.toPurl(d);
            if (purl == null) {
                d.vulnChecked = true;
                d.queryStatus = "无有效版本(未锁定/变量)，跳过漏洞查询";
                d.queryMethod = "-";
                continue;
            }
            targets.add(d);
            purls.add(purl);
        }
        if (targets.isEmpty()) return 0;
        log.accept(I18n.tag("log.tag.query") + I18n.get("log.query.iq", targets.size(), cfg.iqServerUrl));
        Map<String, IqServerChecker.IqResult> result = IqServerChecker.query(purls, cfg.iqServerUrl, cfg.iqToken, log);
        int ok = 0;
        for (int i = 0; i < targets.size(); i++) {
            Dependency d = targets.get(i);
            String purl = purls.get(i);
            IqServerChecker.IqResult r = result.get(purl);
            if (r != null && r.success) {
                mergeVulns(d, r.vulns);
                if (d.license.isEmpty()) d.license = r.license;
                d.vulnChecked = true;
                d.queryStatus = "exact".equals(r.matchState) ? "成功" : "成功(匹配状态: " + r.matchState + ")";
                d.queryMethod = "Sonatype IQ";
                ok++;
                logDepResult(d, "Sonatype IQ", log);
            } else {
                d.queryStatus = "IQ Server 未返回该组件结果";
            }
        }
        return ok;
    }

    /**
     * 汇总官方修复版本建议：优先复用各通道查询结果中的修复版本，
     * 非 OSV 通道未提供时用 OSV 补充查询，并记录接口读取日期。
     */
    private void summarizeFixSuggestions(List<Dependency> deps, Consumer<String> log) {
        for (Dependency d : deps) {
            if (d.cveList.isEmpty()) continue;
            Set<String> fixes = new LinkedHashSet<String>();
            for (VulnDetail v : d.cveList) {
                if (v.fixVersion != null && !v.fixVersion.isEmpty()) fixes.add(v.fixVersion);
            }
            if (fixes.isEmpty() && !d.queryMethod.contains("OSV")) {
                // 非 OSV 通道未给出修复版本时，用 OSV 补充查询官方修复版本
                List<String> extra = OsvChecker.queryFixVersions(d, log);
                if (!extra.isEmpty()) {
                    fixes.addAll(extra);
                    log.accept(I18n.tag("log.tag.fix") + I18n.get("log.fix.osvExtra", d.display(), extra));
                }
            }
            if (!fixes.isEmpty()) {
                d.apiFixSuggestion = I18n.get("log.fix.suggest", pickBestVersion(fixes), fixSourceName(d));
                d.fixSuggestionDate = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
                log.accept(I18n.tag("log.tag.fix") + d.display() + " → " + d.apiFixSuggestion);
            }
        }
    }

    private static String fixSourceName(Dependency d) {
        String m = d.queryMethod;
        return (m.isEmpty() || "-".equals(m)) ? I18n.get("fix.source.default") : m;
    }

    /** 从修复版本集合中选出最高版本（按数字分段比较） */
    private static String pickBestVersion(Set<String> versions) {
        String best = null;
        for (String v : versions) {
            if (best == null || compareVersion(v, best) > 0) best = v;
        }
        return best == null ? "" : best;
    }

    private static int compareVersion(String a, String b) {
        String[] pa = a.split("[.\\-_]");
        String[] pb = b.split("[.\\-_]");
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            int x = i < pa.length ? versionNum(pa[i]) : 0;
            int y = i < pb.length ? versionNum(pb[i]) : 0;
            if (x != y) return Integer.compare(x, y);
        }
        return 0;
    }

    private static int versionNum(String s) {
        Matcher m = Pattern.compile("\\d+").matcher(s);
        return m.find() ? Integer.parseInt(m.group()) : 0;
    }

    /** 打印单个组件查询结果到显示台 */
    private void logDepResult(Dependency d, String method, Consumer<String> log) {
        if (d.isHasVuln()) {
            StringBuilder ids = new StringBuilder();
            for (VulnDetail v : d.cveList) {
                if (ids.length() > 80) {
                    ids.append(I18n.get("log.query.idsMore", d.cveList.size()));
                    break;
                }
                if (ids.length() > 0) ids.append(", ");
                ids.append(v.cveId);
            }
            log.accept(I18n.tag("log.tag.query") + d.display() + " (" + langLabel(d) + ") " + method + " → "
                    + I18n.get("log.query.osvFound", d.cveList.size(), I18n.severity(d.getMaxSeverityLabel()), ids.toString()));
        } else {
            log.accept(I18n.tag("log.tag.query") + d.display() + " (" + langLabel(d) + ") " + method + " → "
                    + I18n.get("log.query.osvNone"));
        }
    }

    private static String langLabel(Dependency d) {
        return I18n.localizeValue(d.language.getLabel());
    }

    private void mergeVulns(Dependency d, List<VulnDetail> vulns) {
        Set<String> seen = new LinkedHashSet<String>();
        for (VulnDetail v : d.cveList) seen.add(v.cveId);
        for (VulnDetail v : vulns) {
            if (v.cveId.isEmpty()) continue;
            if (seen.add(v.cveId)) {
                d.cveList.add(v);
            } else {
                // 已存在同 CVE：补齐描述信息
                for (VulnDetail exist : d.cveList) {
                    if (exist.cveId.equals(v.cveId)) {
                        if (exist.title.isEmpty()) exist.title = v.title;
                        if (exist.description.isEmpty()) exist.description = v.description;
                        if (exist.cvssScore <= 0) exist.cvssScore = v.cvssScore;
                        if ("未知".equals(exist.severityLabel)) exist.severityLabel = v.severityLabel;
                        break;
                    }
                }
            }
        }
    }

    private void removeChecked(List<Dependency> deps) {
        deps.removeIf(Dependency::isVulnChecked);
    }

    private static String methodName(String m) {
        if (AppConfig.METHOD_OSS_INDEX.equals(m)) return I18n.get("query.methodName.oss");
        if (AppConfig.METHOD_MVN_REPO.equals(m)) return I18n.get("query.methodName.mvn");
        if (AppConfig.METHOD_IQ_SERVER.equals(m)) return I18n.get("query.methodName.iq");
        if (AppConfig.METHOD_OSV.equals(m)) return I18n.get("query.methodName.osv");
        return m;
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignored) {
        }
    }
}
