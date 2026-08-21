package com.qcoder.cve.excel;

import com.qcoder.cve.i18n.I18n;
import com.qcoder.cve.model.Dependency;
import com.qcoder.cve.model.VulnDetail;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

/**
 * 生成 Excel 审计报告（.xlsx）：
 * Sheet1 依赖组件清单（含漏洞状态与许可协议）；
 * Sheet2 CVE漏洞明细；
 * Sheet3 AI项目分析报告。
 */
public class ExcelReport {

    public static void write(File file, List<Dependency> deps, String aiAnalysis, String aiFixReport) throws IOException {
        XSSFWorkbook wb = new XSSFWorkbook();

        CellStyle headerStyle = wb.createCellStyle();
        headerStyle.setFillForegroundColor(IndexedColors.DARK_BLUE.getIndex());
        headerStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
        headerStyle.setFont(font(wb, true, IndexedColors.WHITE.getIndex()));
        headerStyle.setAlignment(HorizontalAlignment.CENTER);
        headerStyle.setVerticalAlignment(VerticalAlignment.CENTER);
        headerStyle.setBorderBottom(BorderStyle.THIN);
        headerStyle.setBorderTop(BorderStyle.THIN);
        headerStyle.setBorderLeft(BorderStyle.THIN);
        headerStyle.setBorderRight(BorderStyle.THIN);

        CellStyle baseStyle = wb.createCellStyle();
        baseStyle.setWrapText(true);
        baseStyle.setVerticalAlignment(VerticalAlignment.CENTER);
        baseStyle.setBorderBottom(BorderStyle.THIN);
        baseStyle.setBorderTop(BorderStyle.THIN);
        baseStyle.setBorderLeft(BorderStyle.THIN);
        baseStyle.setBorderRight(BorderStyle.THIN);

        CellStyle redStyle = wb.createCellStyle();
        copy(baseStyle, redStyle);
        redStyle.setFillForegroundColor(IndexedColors.ROSE.getIndex());
        redStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);

        CellStyle greenStyle = wb.createCellStyle();
        copy(baseStyle, greenStyle);
        greenStyle.setFillForegroundColor(IndexedColors.LIGHT_GREEN.getIndex());
        greenStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);

        CellStyle yellowStyle = wb.createCellStyle();
        copy(baseStyle, yellowStyle);
        yellowStyle.setFillForegroundColor(IndexedColors.LIGHT_YELLOW.getIndex());
        yellowStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);

        // ---------- Sheet1 依赖组件清单 ----------
        Sheet sheet1 = wb.createSheet(I18n.get("excel.sheet1"));
        String[] headers1 = {I18n.get("excel.h1.no"), I18n.get("excel.h1.pkg"), I18n.get("excel.h1.ver"),
                I18n.get("excel.h1.lang"), I18n.get("excel.h1.intro"), I18n.get("excel.h1.src"),
                I18n.get("excel.h1.proj"), I18n.get("excel.h1.vuln"), I18n.get("excel.h1.vulnCount"),
                I18n.get("excel.h1.maxSev"), I18n.get("excel.h1.cves"), I18n.get("excel.h1.lic"),
                I18n.get("excel.h1.fix"), I18n.get("excel.h1.fixDate"), I18n.get("excel.h1.method"),
                I18n.get("excel.h1.status")};
        Row headerRow = sheet1.createRow(0);
        for (int i = 0; i < headers1.length; i++) {
            Cell c = headerRow.createCell(i);
            c.setCellValue(headers1[i]);
            c.setCellStyle(headerStyle);
        }
        int[] widths1 = {6, 36, 14, 12, 18, 40, 16, 12, 10, 12, 55, 30, 45, 16, 14, 22};
        for (int i = 0; i < widths1.length; i++) {
            sheet1.setColumnWidth(i, widths1[i] * 256);
        }
        sheet1.setAutoFilter(new CellRangeAddress(0, 0, 0, headers1.length - 1));
        sheet1.createFreezePane(0, 1);

        int r = 1;
        for (Dependency d : deps) {
            Row row = sheet1.createRow(r++);
            CellStyle rowStyle = d.isHasVuln() ? redStyle : (d.vulnChecked ? greenStyle : baseStyle);
            row.createCell(0).setCellValue(r - 1);
            row.createCell(1).setCellValue(d.packageId);
            row.createCell(2).setCellValue(d.versionVariable ? d.version + I18n.get("excel.readVarSuffix") : d.version);
            row.createCell(3).setCellValue(I18n.localizeValue(d.language.getLabel()));
            row.createCell(4).setCellValue(d.introduceType);
            row.createCell(5).setCellValue(d.sourceFile);
            row.createCell(6).setCellValue(d.projectName);
            row.createCell(7).setCellValue(d.isHasVuln() ? I18n.get("common.yes") : (d.vulnChecked ? I18n.get("common.no") : I18n.get("common.notQueried")));
            row.createCell(8).setCellValue(d.cveList.size());
            row.createCell(9).setCellValue(d.isHasVuln() ? I18n.severity(d.getMaxSeverityLabel()) : "");
            row.createCell(10).setCellValue(d.getCveIdsText());
            row.createCell(11).setCellValue(I18n.localizeValue(d.license));
            String fix = d.aiFixSuggestion;
            if (fix.isEmpty()) fix = d.apiFixSuggestion;
            row.createCell(12).setCellValue(fix);
            row.createCell(13).setCellValue(d.fixSuggestionDate);
            row.createCell(14).setCellValue(d.queryMethod);
            row.createCell(15).setCellValue(I18n.localizeStatus(d.queryStatus));
            for (int i = 0; i < headers1.length; i++) {
                row.getCell(i).setCellStyle(rowStyle);
            }
        }

        // ---------- Sheet2 CVE漏洞明细 ----------
        Sheet sheet2 = wb.createSheet(I18n.get("excel.sheet2"));
        String[] headers2 = {I18n.get("excel.h2.no"), I18n.get("excel.h2.pkg"), I18n.get("excel.h2.ver"),
                I18n.get("excel.h2.lang"), I18n.get("excel.h2.cve"), I18n.get("excel.h2.sev"),
                I18n.get("excel.h2.score"), I18n.get("excel.h2.title"), I18n.get("excel.h2.desc"),
                I18n.get("excel.h2.affected"), I18n.get("excel.h2.ref")};
        Row h2 = sheet2.createRow(0);
        for (int i = 0; i < headers2.length; i++) {
            Cell c = h2.createCell(i);
            c.setCellValue(headers2[i]);
            c.setCellStyle(headerStyle);
        }
        int[] widths2 = {6, 36, 14, 12, 18, 12, 10, 35, 70, 35, 45};
        for (int i = 0; i < widths2.length; i++) {
            sheet2.setColumnWidth(i, widths2[i] * 256);
        }
        sheet2.setAutoFilter(new CellRangeAddress(0, 0, 0, headers2.length - 1));
        sheet2.createFreezePane(0, 1);

        r = 1;
        for (Dependency d : deps) {
            for (VulnDetail v : d.cveList) {
                Row row = sheet2.createRow(r++);
                CellStyle style = baseStyle;
                if ("严重".equals(v.severityLabel)) style = redStyle;
                else if ("高危".equals(v.severityLabel)) style = redStyle;
                else if ("中危".equals(v.severityLabel)) style = yellowStyle;
                row.createCell(0).setCellValue(r - 1);
                row.createCell(1).setCellValue(d.packageId);
                row.createCell(2).setCellValue(d.version);
                row.createCell(3).setCellValue(I18n.localizeValue(d.language.getLabel()));
                row.createCell(4).setCellValue(v.cveId);
                row.createCell(5).setCellValue(I18n.severity(v.severityLabel));
                if (v.cvssScore > 0) row.createCell(6).setCellValue(v.cvssScore);
                else row.createCell(6).setCellValue("");
                row.createCell(7).setCellValue(v.title);
                row.createCell(8).setCellValue(v.description);
                row.createCell(9).setCellValue(v.affectedVersions);
                row.createCell(10).setCellValue(v.reference);
                for (int i = 0; i < headers2.length; i++) {
                    row.getCell(i).setCellStyle(style);
                }
            }
        }

        // ---------- Sheet3 AI项目分析报告 ----------
        Sheet sheet3 = wb.createSheet(I18n.get("excel.sheet3"));
        sheet3.setColumnWidth(0, 140 * 256);
        Row t3 = sheet3.createRow(0);
        t3.createCell(0).setCellValue(I18n.get("excel.sheet3.title"));
        t3.getCell(0).setCellStyle(headerStyle);
        sheet3.createFreezePane(0, 1);

        if (aiAnalysis != null && !aiAnalysis.isEmpty()) {
            int r3 = 1;
            for (String line : aiAnalysis.split("\n")) {
                Row row = sheet3.createRow(r3++);
                row.createCell(0).setCellValue(line);
                row.getCell(0).setCellStyle(baseStyle);
            }
        } else {
            Row row = sheet3.createRow(1);
            row.createCell(0).setCellValue(I18n.get("excel.sheet3.noContent"));
        }

        // AI 修复建议报告
        if (aiFixReport != null && !aiFixReport.isEmpty()) {
            int r3 = sheet3.getLastRowNum() + 2;
            Row title = sheet3.createRow(r3++);
            title.createCell(0).setCellValue(I18n.get("excel.sheet3.fixTitle"));
            title.getCell(0).setCellStyle(headerStyle);
            for (String line : aiFixReport.split("\n")) {
                Row row = sheet3.createRow(r3++);
                row.createCell(0).setCellValue(line);
                row.getCell(0).setCellStyle(baseStyle);
            }
        }

        FileOutputStream fos = new FileOutputStream(file);
        wb.write(fos);
        fos.close();
        wb.close();
    }

    private static Font font(Workbook wb, boolean bold, short color) {
        Font f = wb.createFont();
        f.setBold(bold);
        f.setFontHeightInPoints((short) 11);
        f.setColor(color);
        return f;
    }

    private static void copy(CellStyle from, CellStyle to) {
        to.setWrapText(from.getWrapText());
        to.setVerticalAlignment(from.getVerticalAlignment());
        to.setBorderBottom(from.getBorderBottom());
        to.setBorderTop(from.getBorderTop());
        to.setBorderLeft(from.getBorderLeft());
        to.setBorderRight(from.getBorderRight());
    }

    /**
     * 从 Excel 读取依赖组件清单（兼容本工具生成或用户外部生成/精简/自定义格式）。
     * 表头按关键词模糊匹配：组件名称(packageId)、版本、语言、引入方式、许可协议等列均可选。
     *
     * @throws IOException 文件无法读取或找不到组件名称列时抛出
     */
    public static List<Dependency> readDependencies(File file) throws IOException {
        List<Dependency> deps = new ArrayList<Dependency>();
        Workbook wb = WorkbookFactory.create(file);
        try {
            // 优先取名称含“依赖/清单”的 sheet，否则取第一个（跳过 CVE 明细表）
            Sheet sheet = wb.getSheetAt(0);
            for (int i = 0; i < wb.getNumberOfSheets(); i++) {
                Sheet s = wb.getSheetAt(i);
                if (s.getSheetName().contains("CVE")) continue;
                if (s.getSheetName().contains("依赖") || s.getSheetName().contains("清单")
                        || s.getSheetName().toLowerCase().contains("component")
                        || s.getSheetName().toLowerCase().contains("list")) {
                    sheet = s;
                    break;
                }
            }

            // 定位表头行（前 5 行内包含组件名称/packageId 等关键词的行）
            Row header = null;
            int headerRowIdx = -1;
            for (int r = 0; r < Math.min(5, sheet.getLastRowNum() + 1); r++) {
                Row row = sheet.getRow(r);
                if (row == null) continue;
                StringBuilder line = new StringBuilder();
                for (int c = 0; c < row.getLastCellNum(); c++) {
                    String v = cellStr(row.getCell(c));
                    if (!v.isEmpty()) line.append(v).append(" ");
                }
                String lower = line.toString().toLowerCase();
                if (lower.contains("packageid") || lower.contains("组件名称") || lower.contains("组件名")
                        || lower.contains("component") || lower.contains("package")
                        || (lower.contains("version") && (lower.contains("组件") || lower.contains("依赖")
                        || lower.contains("dependency")))) {
                    header = row;
                    headerRowIdx = r;
                    break;
                }
            }
            if (header == null) {
                throw new IOException(I18n.get("excel.readNoHeader"));
            }

            // 列映射（表头关键词匹配，兼容中英文）
            int colPkg = -1, colVer = -1, colLang = -1, colIntro = -1, colLic = -1, colSrc = -1, colProj = -1, colGroup = -1, colArt = -1;
            for (int c = 0; c < header.getLastCellNum(); c++) {
                String h = cellStr(header.getCell(c)).trim().toLowerCase().replace(" ", "").replace("_", "");
                if (h.isEmpty()) continue;
                if (colPkg < 0 && (h.contains("packageid") || h.contains("组件名称") || h.contains("组件名")
                        || h.equals("组件") || h.contains("包名") || h.contains("component")
                        || h.equals("package") || h.equals("name"))) colPkg = c;
                if (colGroup < 0 && (h.equals("group") || h.contains("groupid") || h.contains("组名") || h.contains("组id"))) colGroup = c;
                if (colArt < 0 && (h.equals("artifact") || h.contains("artifactid") || h.contains("构件"))) colArt = c;
                if (colVer < 0 && (h.contains("version") || h.contains("版本"))) colVer = c;
                if (colLang < 0 && (h.contains("language") || h.contains("语言"))) colLang = c;
                if (colIntro < 0 && (h.contains("引入") || h.contains("introduce") || h.contains("scope") || h.contains("作用域"))) colIntro = c;
                if (colLic < 0 && (h.contains("license") || h.contains("许可"))) colLic = c;
                if (colSrc < 0 && (h.contains("sourcefile") || h.contains("配置") || h.contains("文件位置"))) colSrc = c;
                if (colProj < 0 && (h.contains("project") || h.contains("项目"))) colProj = c;
            }
            if (colPkg < 0 && !(colGroup >= 0 && colArt >= 0)) {
                throw new IOException(I18n.get("excel.readNoCol"));
            }

            for (int r = headerRowIdx + 1; r <= sheet.getLastRowNum(); r++) {
                Row row = sheet.getRow(r);
                if (row == null) continue;
                String pkg = colPkg >= 0 ? cellStr(row.getCell(colPkg)).trim() : "";
                // 无组件名称列时，由 Group ID + Artifact ID 两列拼接
                if (pkg.isEmpty() && colGroup >= 0 && colArt >= 0) {
                    pkg = cellStr(row.getCell(colGroup)).trim() + ":" + cellStr(row.getCell(colArt)).trim();
                }
                if (pkg.isEmpty()) continue;
                if (pkg.matches("^\\d+(\\.\\d+)?$")) continue; // 纯数字(如序号残留)

                Dependency d = new Dependency();
                d.packageId = pkg;
                d.version = colVer >= 0 ? cellStr(row.getCell(colVer)).trim() : "";
                if (d.version.isEmpty()) d.version = "未锁定";
                if (d.version.endsWith(" (变量)")) {
                    d.version = d.version.substring(0, d.version.length() - " (变量)".length()).trim();
                    d.versionVariable = true;
                }
                d.language = colLang >= 0 ? Dependency.Language.parse(cellStr(row.getCell(colLang))) : Dependency.Language.UNKNOWN;
                if (d.language == Dependency.Language.UNKNOWN && d.packageId.contains(":")) d.language = Dependency.Language.JAVA;
                d.introduceType = colIntro >= 0 ? cellStr(row.getCell(colIntro)).trim() : I18n.get("excel.readIntro");
                if (d.introduceType.isEmpty()) d.introduceType = I18n.get("excel.readIntro");
                d.license = colLic >= 0 ? cellStr(row.getCell(colLic)).trim() : "";
                d.sourceFile = colSrc >= 0 ? cellStr(row.getCell(colSrc)).trim() : I18n.get("excel.readIntro");
                d.projectName = colProj >= 0 ? cellStr(row.getCell(colProj)).trim() : "";
                if (d.language == Dependency.Language.JAVA && d.packageId.contains(":")) {
                    int idx = d.packageId.indexOf(':');
                    d.groupId = d.packageId.substring(0, idx);
                    d.artifactId = d.packageId.substring(idx + 1);
                } else {
                    d.artifactId = d.packageId;
                }
                deps.add(d);
            }
        } finally {
            wb.close();
        }
        return deps;
    }

    private static String cellStr(Cell c) {
        if (c == null) return "";
        switch (c.getCellType()) {
            case STRING:
                return c.getStringCellValue();
            case NUMERIC:
                if (DateUtil.isCellDateFormatted(c)) return c.getDateCellValue().toString();
                return BigDecimal.valueOf(c.getNumericCellValue()).stripTrailingZeros().toPlainString();
            case BOOLEAN:
                return String.valueOf(c.getBooleanCellValue());
            case FORMULA:
                try {
                    return c.getCellFormula();
                } catch (Exception e) {
                    return "";
                }
            default:
                return "";
        }
    }
}
