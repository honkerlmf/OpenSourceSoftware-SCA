package com.qcoder.cve.ui;

import com.qcoder.cve.ai.AiClient;
import com.qcoder.cve.ai.AiService;
import com.qcoder.cve.config.AppConfig;
import com.qcoder.cve.config.ConfigStore;
import com.qcoder.cve.cve.CveQueryService;
import com.qcoder.cve.excel.ExcelReport;
import com.qcoder.cve.i18n.I18n;
import com.qcoder.cve.model.Dependency;
import com.qcoder.cve.scan.DependencyScanner;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 主界面：AI模型配置 / 漏洞查询配置 / 依赖扫描与漏洞分析 三个页签 + 日志区。
 */
public class MainFrame extends JFrame {

    private AppConfig cfg;
    private final JTabbedPane tabbed = new JTabbedPane();

    // ---- AI 配置 ----
    private final JTextField extUrl = new JTextField();
    private final JPasswordField extKey = new JPasswordField();
    private final JTextField extModel = new JTextField();
    private final JTextField extTimeout = new JTextField("60");
    private final JTextField intUrl = new JTextField();
    private final JTextField intKey = new JTextField();
    private final JTextField intModel = new JTextField();
    private final JTextField intTimeout = new JTextField("120");
    private final JRadioButton rbExtAi = new JRadioButton(I18n.get("ai.useExt"));
    private final JRadioButton rbIntAi = new JRadioButton(I18n.get("ai.useInt"));

    // ---- 查询配置 ----
    private final JRadioButton rbOsv = new JRadioButton(I18n.get("query.rbOsv"));
    private final JRadioButton rbOss = new JRadioButton(I18n.get("query.rbOss"));
    private final JRadioButton rbMvn = new JRadioButton(I18n.get("query.rbMvn"));
    private final JRadioButton rbIq = new JRadioButton(I18n.get("query.rbIq"));
    private final JTextField iqServerUrl = new JTextField();
    private final JPasswordField iqToken = new JPasswordField();
    private final JCheckBox chkFallback = new JCheckBox(I18n.get("query.chkFallback"), true);
    private final JCheckBox chkLicense = new JCheckBox(I18n.get("query.chkLicense"), true);

    // ---- 扫描页 ----
    private final JRadioButton rbScanProject = new JRadioButton(I18n.get("scan.rbProject"));
    private final JRadioButton rbScanLib = new JRadioButton(I18n.get("scan.rbLib"));
    private final JRadioButton rbScanArchive = new JRadioButton(I18n.get("scan.rbArchive"));
    private final JTextField folderField = new JTextField();
    private final JTextField excelListField = new JTextField();
    private final JTextField outputField = new JTextField();
    private final JCheckBox chkAiAnalyze = new JCheckBox(I18n.get("scan.chkAiAnalyze"), true);
    private final JCheckBox chkAiFix = new JCheckBox(I18n.get("scan.chkAiFix"), true);
    private final JButton btnScan = new JButton(I18n.get("scan.btnScan"));
    private final JButton btnQuery = new JButton(I18n.get("scan.btnQuery"));
    private final JButton btnOneClick = new JButton(I18n.get("scan.btnOneClick"));
    private final JButton btnOpenExcel = new JButton(I18n.get("scan.btnOpenExcel"));
    private final JProgressBar progressBar = new JProgressBar();

    // ---- 日志 ----
    private final JTextArea logArea = new JTextArea();
    private final JScrollPane logScroll = new JScrollPane(logArea);

    // ---- 状态 ----
    private List<Dependency> lastDeps = new ArrayList<Dependency>();
    private String lastAiAnalysis = "";
    private String lastScannedFolder = "";

    public MainFrame() {
        super(I18n.get("app.title"));
        cfg = ConfigStore.load();
        I18n.setLanguage(cfg.language);

        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1080, 760);
        setLocationRelativeTo(null);

        setJMenuBar(buildMenuBar());
        addScanListeners();
        refreshTexts();
        tabbed.addTab(I18n.get("app.tab.ai"), buildAiPanel());
        tabbed.addTab(I18n.get("app.tab.query"), buildQueryPanel());
        tabbed.addTab(I18n.get("app.tab.scan"), buildScanPanel());
        add(tabbed, BorderLayout.CENTER);
        add(buildBottomPanel(), BorderLayout.SOUTH);

        loadCfgToUi();

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                saveCfg();
            }
        });

        log(I18n.get("app.welcome"));
        log(I18n.get("app.steps"));
    }

    // ==================== 语言切换 ====================

    private JMenuBar buildMenuBar() {
        JMenuBar bar = new JMenuBar();
        JMenu langMenu = new JMenu(I18n.get("menu.language"));
        JMenuItem miZh = new JMenuItem(I18n.get("menu.lang.zh"));
        miZh.addActionListener(e -> switchLanguage(I18n.ZH));
        JMenuItem miEn = new JMenuItem(I18n.get("menu.lang.en"));
        miEn.addActionListener(e -> switchLanguage(I18n.EN));
        JMenuItem miFr = new JMenuItem(I18n.get("menu.lang.fr"));
        miFr.addActionListener(e -> switchLanguage(I18n.FR));
        JMenuItem miJa = new JMenuItem(I18n.get("menu.lang.ja"));
        miJa.addActionListener(e -> switchLanguage(I18n.JA));
        langMenu.add(miZh);
        langMenu.add(miEn);
        langMenu.add(miFr);
        langMenu.add(miJa);
        bar.add(langMenu);
        return bar;
    }

    /** 切换界面语言：更新资源包、持久化配置、重建界面 */
    private void switchLanguage(String lang) {
        I18n.setLanguage(lang);
        cfg.language = lang;
        saveCfg();
        rebuildUi();
        log(I18n.get("lang.switched", langDisplay(lang)));
    }

    private static String langDisplay(String lang) {
        if (I18n.EN.equals(lang)) return "English";
        if (I18n.FR.equals(lang)) return "Français";
        if (I18n.JA.equals(lang)) return "日本語";
        return "简体中文";
    }

    /** 按当前语言重建整个界面（页签内容 + 菜单栏 + 标题），日志区保留 */
    private void rebuildUi() {
        tabbed.removeAll();
        tabbed.addTab(I18n.get("app.tab.ai"), buildAiPanel());
        tabbed.addTab(I18n.get("app.tab.query"), buildQueryPanel());
        tabbed.addTab(I18n.get("app.tab.scan"), buildScanPanel());
        getContentPane().removeAll();
        getContentPane().add(tabbed, BorderLayout.CENTER);
        getContentPane().add(buildBottomPanel(), BorderLayout.SOUTH);
        setJMenuBar(buildMenuBar());
        refreshTexts();
        getContentPane().validate();
        getContentPane().repaint();
    }

    /** 刷新所有固定组件文本（语言切换/首次构建时调用） */
    private void refreshTexts() {
        setTitle(I18n.get("app.title"));
        rbExtAi.setText(I18n.get("ai.useExt"));
        rbIntAi.setText(I18n.get("ai.useInt"));
        rbOsv.setText(I18n.get("query.rbOsv"));
        rbOss.setText(I18n.get("query.rbOss"));
        rbMvn.setText(I18n.get("query.rbMvn"));
        rbIq.setText(I18n.get("query.rbIq"));
        chkFallback.setText(I18n.get("query.chkFallback"));
        chkLicense.setText(I18n.get("query.chkLicense"));
        rbScanProject.setText(I18n.get("scan.rbProject"));
        rbScanLib.setText(I18n.get("scan.rbLib"));
        rbScanArchive.setText(I18n.get("scan.rbArchive"));
        chkAiAnalyze.setText(I18n.get("scan.chkAiAnalyze"));
        chkAiFix.setText(I18n.get("scan.chkAiFix"));
        btnScan.setText(I18n.get("scan.btnScan"));
        btnQuery.setText(I18n.get("scan.btnQuery"));
        btnOneClick.setText(I18n.get("scan.btnOneClick"));
        btnOpenExcel.setText(I18n.get("scan.btnOpenExcel"));
    }

    /** 扫描页四个按钮的监听器（仅注册一次，避免界面重建时重复触发） */
    private void addScanListeners() {
        btnScan.addActionListener(e -> startScan(false));
        btnQuery.addActionListener(e -> startQuery(false));
        btnOneClick.addActionListener(e -> startQuery(true));
        btnOpenExcel.addActionListener(e -> openExcel());
    }

    // ==================== UI 构建 ====================

    private JPanel buildAiPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(12, 12, 12, 12));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(6, 6, 6, 6);
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 1;

        // 外网AI
        JPanel extPanel = new JPanel(new GridBagLayout());
        extPanel.setBorder(new TitledBorder(I18n.get("ai.ext.title")));
        addRow(extPanel, 0, I18n.get("ai.baseUrl"), extUrl, "");
        addRow(extPanel, 1, I18n.get("ai.apiKey"), extKey, "");
        addRow(extPanel, 2, I18n.get("ai.model"), extModel, "");
        addRow(extPanel, 3, I18n.get("ai.timeout"), extTimeout, "");
        JButton btnTestExt = new JButton(I18n.get("ai.testExt"));
        btnTestExt.addActionListener(e -> testAi(true));
        addRow(extPanel, 4, "", btnTestExt, "");

        // 内网AI
        JPanel intPanel = new JPanel(new GridBagLayout());
        intPanel.setBorder(new TitledBorder(I18n.get("ai.int.title")));
        addRow(intPanel, 0, I18n.get("ai.baseUrl"), intUrl, "");
        addRow(intPanel, 1, I18n.get("ai.apiKeyOpt"), intKey, "");
        addRow(intPanel, 2, I18n.get("ai.model"), intModel, "");
        addRow(intPanel, 3, I18n.get("ai.timeout"), intTimeout, "");
        JButton btnTestInt = new JButton(I18n.get("ai.testInt"));
        btnTestInt.addActionListener(e -> testAi(false));
        addRow(intPanel, 4, "", btnTestInt, "");

        ButtonGroup grp = new ButtonGroup();
        grp.add(rbExtAi);
        grp.add(rbIntAi);

        JPanel choosePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        choosePanel.setBorder(new TitledBorder(I18n.get("ai.choose.title")));
        choosePanel.add(rbExtAi);
        choosePanel.add(rbIntAi);

        JButton btnSave = new JButton(I18n.get("ai.save"));
        btnSave.addActionListener(e -> {
            saveCfg();
            log(I18n.tag("log.tag.cfg") + I18n.get("log.cfg.saved", ConfigStore.getConfigFile().getAbsolutePath()));
        });

        g.gridx = 0;
        g.gridy = 0;
        g.weighty = 0;
        panel.add(extPanel, g);
        g.gridy = 1;
        panel.add(intPanel, g);
        g.gridy = 2;
        panel.add(choosePanel, g);
        g.gridy = 3;
        panel.add(btnSave, g);
        return panel;
    }

    private JPanel buildQueryPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(12, 12, 12, 12));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(6, 6, 6, 6);
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 1;

        JPanel methodPanel = new JPanel(new GridBagLayout());
        methodPanel.setBorder(new TitledBorder(I18n.get("query.method.title")));
        ButtonGroup grp = new ButtonGroup();
        grp.add(rbOsv);
        grp.add(rbOss);
        grp.add(rbMvn);
        grp.add(rbIq);
        GridBagConstraints mg = new GridBagConstraints();
        mg.insets = new Insets(4, 8, 4, 8);
        mg.gridx = 0;
        mg.gridy = 0;
        mg.anchor = GridBagConstraints.WEST;
        methodPanel.add(rbOsv, mg);
        mg.gridy = 1;
        methodPanel.add(rbOss, mg);
        mg.gridy = 2;
        methodPanel.add(rbMvn, mg);
        mg.gridy = 3;
        methodPanel.add(rbIq, mg);
        mg.gridy = 4;
        mg.fill = GridBagConstraints.HORIZONTAL;
        JPanel iqRow = new JPanel(new BorderLayout(6, 6));
        JPanel iqLeft = new JPanel(new GridLayout(2, 1, 4, 4));
        iqLeft.add(new JLabel(I18n.get("query.iqUrl")));
        iqLeft.add(new JLabel(I18n.get("query.iqToken")));
        JPanel iqRight = new JPanel(new GridLayout(2, 1, 4, 4));
        iqRight.add(iqServerUrl);
        iqRight.add(iqToken);
        iqRow.add(iqLeft, BorderLayout.WEST);
        iqRow.add(iqRight, BorderLayout.CENTER);
        methodPanel.add(iqRow, mg);

        g.gridx = 0;
        g.gridy = 0;
        panel.add(methodPanel, g);
        g.gridy = 1;
        JPanel optPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        optPanel.setBorder(new TitledBorder(I18n.get("query.opt.title")));
        optPanel.add(chkFallback);
        optPanel.add(chkLicense);
        panel.add(optPanel, g);
        g.gridy = 2;
        JLabel tip = new JLabel(I18n.get("query.tip"));
        tip.setForeground(new Color(90, 90, 90));
        panel.add(tip, g);
        return panel;
    }

    private JPanel buildScanPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(12, 12, 12, 12));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(6, 6, 6, 6);
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 1;

        JPanel modeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        modeRow.setBorder(new TitledBorder(I18n.get("scan.mode.title")));
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(rbScanProject);
        modeGroup.add(rbScanLib);
        modeGroup.add(rbScanArchive);
        modeRow.add(rbScanProject);
        modeRow.add(rbScanLib);
        modeRow.add(rbScanArchive);
        rbScanProject.setSelected(true);

        JPanel folderRow = new JPanel(new BorderLayout(6, 6));
        folderRow.add(new JLabel(I18n.get("scan.target")), BorderLayout.WEST);
        folderRow.add(folderField, BorderLayout.CENTER);
        JButton btnFolder = new JButton(I18n.get("scan.browse"));
        btnFolder.addActionListener(e -> chooseFolder());
        folderRow.add(btnFolder, BorderLayout.EAST);

        JPanel excelListRow = new JPanel(new BorderLayout(6, 6));
        excelListRow.add(new JLabel(I18n.get("scan.excelList")), BorderLayout.WEST);
        excelListRow.add(excelListField, BorderLayout.CENTER);
        JButton btnExcelList = new JButton(I18n.get("scan.browse"));
        btnExcelList.addActionListener(e -> chooseExcelList());
        excelListRow.add(btnExcelList, BorderLayout.EAST);

        JPanel outputRow = new JPanel(new BorderLayout(6, 6));
        outputRow.add(new JLabel(I18n.get("scan.output")), BorderLayout.WEST);
        outputRow.add(outputField, BorderLayout.CENTER);
        JButton btnOutput = new JButton(I18n.get("scan.browse"));
        btnOutput.addActionListener(e -> chooseOutput());
        outputRow.add(btnOutput, BorderLayout.EAST);

        JPanel chkRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        chkRow.add(chkAiAnalyze);
        chkRow.add(chkAiFix);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        btnRow.add(btnScan);
        btnRow.add(btnQuery);
        btnRow.add(btnOneClick);
        btnRow.add(btnOpenExcel);

        g.gridx = 0;
        g.gridy = 0;
        panel.add(modeRow, g);
        g.gridy = 1;
        panel.add(folderRow, g);
        g.gridy = 2;
        panel.add(excelListRow, g);
        g.gridy = 3;
        panel.add(outputRow, g);
        g.gridy = 4;
        panel.add(chkRow, g);
        g.gridy = 5;
        panel.add(btnRow, g);
        g.gridy = 6;
        panel.add(new JLabel(I18n.get("scan.hint")), g);
        return panel;
    }

    private JPanel buildBottomPanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 4));
        panel.setBorder(new EmptyBorder(6, 10, 8, 10));
        progressBar.setStringPainted(true);
        progressBar.setString(I18n.get("scan.ready"));
        panel.add(progressBar, BorderLayout.NORTH);
        logArea.setEditable(false);
        logArea.setFont(logFont());
        logScroll.setPreferredSize(new Dimension(0, 170));
        panel.add(logScroll, BorderLayout.CENTER);
        return panel;
    }

    /** 选择支持中文的日志字体，避免 Consolas 等字体显示中文乱码 */
    private static Font logFont() {
        String[] candidates = {"Microsoft YaHei", "微软雅黑", "SimSun", "宋体", "Consolas"};
        for (String name : candidates) {
            Font f = new Font(name, Font.PLAIN, 12);
            if (f.canDisplay('扫') && f.canDisplay('漏')) return f;
        }
        return new Font(Font.MONOSPACED, Font.PLAIN, 12);
    }

    private void addRow(JPanel panel, int y, String label, java.awt.Component comp, String hint) {
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(5, 10, 5, 10);
        g.gridy = y;
        g.gridx = 0;
        g.anchor = GridBagConstraints.WEST;
        panel.add(new JLabel(label), g);
        g.gridx = 1;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 1;
        panel.add(comp, g);
        if (comp instanceof JTextField) {
            ((JTextField) comp).setColumns(30);
        }
    }

    // ==================== 配置读写 ====================

    private void loadCfgToUi() {
        cfg.normalize();
        extUrl.setText(cfg.externalAi.baseUrl);
        extKey.setText(cfg.externalAi.apiKey);
        extModel.setText(cfg.externalAi.model);
        extTimeout.setText(String.valueOf(cfg.externalAi.timeoutSec));
        intUrl.setText(cfg.internalAi.baseUrl);
        intKey.setText(cfg.internalAi.apiKey);
        intModel.setText(cfg.internalAi.model);
        intTimeout.setText(String.valueOf(cfg.internalAi.timeoutSec));
        rbExtAi.setSelected(cfg.useExternalAi);
        rbIntAi.setSelected(!cfg.useExternalAi);

        rbOsv.setSelected(AppConfig.METHOD_OSV.equals(cfg.queryMethod));
        rbOss.setSelected(AppConfig.METHOD_OSS_INDEX.equals(cfg.queryMethod));
        rbMvn.setSelected(AppConfig.METHOD_MVN_REPO.equals(cfg.queryMethod));
        rbIq.setSelected(AppConfig.METHOD_IQ_SERVER.equals(cfg.queryMethod));
        iqServerUrl.setText(cfg.iqServerUrl);
        iqToken.setText(cfg.iqToken);
        chkFallback.setSelected(cfg.fallbackEnabled);
        chkLicense.setSelected(cfg.licenseEnabled);

        folderField.setText(cfg.lastFolder);
        excelListField.setText(cfg.excelListFile);
        outputField.setText(cfg.lastOutput);
        chkAiAnalyze.setSelected(cfg.aiAnalyze);
        chkAiFix.setSelected(cfg.aiFix);
        rbScanProject.setSelected(AppConfig.SCAN_MODE_PROJECT.equals(cfg.scanMode));
        rbScanLib.setSelected(AppConfig.SCAN_MODE_LIB_FOLDER.equals(cfg.scanMode));
        rbScanArchive.setSelected(AppConfig.SCAN_MODE_ARCHIVE.equals(cfg.scanMode));
        if (!rbScanProject.isSelected() && !rbScanLib.isSelected() && !rbScanArchive.isSelected()) {
            rbScanProject.setSelected(true);
        }
    }

    private void saveCfg() {
        cfg.normalize();
        cfg.externalAi.baseUrl = extUrl.getText().trim();
        cfg.externalAi.apiKey = new String(extKey.getPassword());
        cfg.externalAi.model = extModel.getText().trim();
        cfg.externalAi.timeoutSec = parseInt(extTimeout.getText(), 60);
        cfg.internalAi.baseUrl = intUrl.getText().trim();
        cfg.internalAi.apiKey = intKey.getText().trim();
        cfg.internalAi.model = intModel.getText().trim();
        cfg.internalAi.timeoutSec = parseInt(intTimeout.getText(), 120);
        cfg.useExternalAi = rbExtAi.isSelected();

        cfg.queryMethod = rbOsv.isSelected() ? AppConfig.METHOD_OSV
                : (rbOss.isSelected() ? AppConfig.METHOD_OSS_INDEX
                : (rbMvn.isSelected() ? AppConfig.METHOD_MVN_REPO : AppConfig.METHOD_IQ_SERVER));
        cfg.iqServerUrl = iqServerUrl.getText().trim();
        cfg.iqToken = new String(iqToken.getPassword());
        cfg.fallbackEnabled = chkFallback.isSelected();
        cfg.licenseEnabled = chkLicense.isSelected();
        cfg.aiAnalyze = chkAiAnalyze.isSelected();
        cfg.aiFix = chkAiFix.isSelected();
        cfg.scanMode = rbScanLib.isSelected() ? AppConfig.SCAN_MODE_LIB_FOLDER
                : (rbScanArchive.isSelected() ? AppConfig.SCAN_MODE_ARCHIVE : AppConfig.SCAN_MODE_PROJECT);
        cfg.lastFolder = folderField.getText().trim();
        cfg.excelListFile = excelListField.getText().trim();
        cfg.lastOutput = outputField.getText().trim();
        try {
            ConfigStore.save(cfg);
        } catch (IOException e) {
            log(I18n.tag("log.tag.warn") + I18n.get("log.cfg.saveFail", e.getMessage()));
        }
    }

    private int parseInt(String s, int def) {
        try {
            int v = Integer.parseInt(s.trim());
            return v > 0 ? v : def;
        } catch (Exception e) {
            return def;
        }
    }

    // ==================== 交互动作 ====================

    private void chooseFolder() {
        JFileChooser chooser = new JFileChooser();
        if (rbScanArchive.isSelected()) {
            chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            chooser.setDialogTitle(I18n.get("scan.choose.title.archive"));
            chooser.setFileFilter(new FileNameExtensionFilter(I18n.get("scan.jarFilter"), "jar", "war", "zip"));
        } else {
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setDialogTitle(rbScanLib.isSelected() ? I18n.get("scan.choose.title.lib") : I18n.get("scan.choose.title.project"));
        }
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            folderField.setText(f.getAbsolutePath());
            if (outputField.getText().trim().isEmpty()) {
                File base = f.isDirectory() ? f : (f.getParentFile() != null ? f.getParentFile() : f);
                outputField.setText(base.getAbsolutePath() + File.separator + I18n.get("scan.defaultOutput"));
            }
        }
    }

    private void chooseOutput() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setDialogTitle(I18n.get("scan.saveAs"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            String path = chooser.getSelectedFile().getAbsolutePath();
            if (!path.toLowerCase().endsWith(".xlsx")) path += ".xlsx";
            outputField.setText(path);
        }
    }

    private void chooseExcelList() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setDialogTitle(I18n.get("scan.excelList.choose"));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            excelListField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void openExcel() {
        String out = outputField.getText().trim();
        if (out.isEmpty()) {
            JOptionPane.showMessageDialog(this, I18n.get("dlg.setOutputFirst"));
            return;
        }
        File f = new File(out);
        if (!f.exists()) {
            JOptionPane.showMessageDialog(this, I18n.get("dlg.excelNotExist"));
            return;
        }
        try {
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().open(f);
            } else {
                JOptionPane.showMessageDialog(this, I18n.get("dlg.openFailEnv", out));
            }
        } catch (Exception e) {
            log(I18n.tag("log.tag.err") + I18n.get("log.excel.openFail", e.getMessage()));
            JOptionPane.showMessageDialog(this, I18n.get("dlg.openExcelFail", e.getMessage()));
        }
    }

    private void testAi(boolean external) {
        saveCfg();
        AppConfig.AiEndpoint ep = external ? cfg.externalAi : cfg.internalAi;
        String tag = I18n.get(external ? "ai.ext" : "ai.int");
        if (ep.baseUrl.isEmpty() || ep.model.isEmpty()) {
            JOptionPane.showMessageDialog(this, I18n.get("ai.fillFirst", tag));
            return;
        }
        AiClient client = new AiClient(ep.baseUrl, ep.apiKey, ep.model, ep.timeoutSec);
        progressBar.setIndeterminate(true);
        progressBar.setString(I18n.get("ai.testConnecting", tag));
        log(I18n.tag("log.tag.ai") + I18n.get("ai.testing", tag, ep.baseUrl, ep.model));
        new SwingWorker<String, String>() {
            @Override
            protected String doInBackground() {
                try {
                    return client.ping();
                } catch (Exception e) {
                    return I18n.get("ai.testFail", e.getMessage());
                }
            }

            @Override
            protected void done() {
                progressBar.setIndeterminate(false);
                progressBar.setString(I18n.get("scan.ready"));
                try {
                    String result = get();
                    log(I18n.tag("log.tag.ai") + I18n.get("ai.testResult", tag, result));
                    JOptionPane.showMessageDialog(MainFrame.this, I18n.get("ai.testResult", tag, result));
                } catch (Exception e) {
                    log(I18n.tag("log.tag.ai") + I18n.get("ai.exception", e.getMessage()));
                }
            }
        }.execute();
    }

    // ==================== 核心流程 ====================

    /** 构建当前配置下的 AI 服务（未配置时返回 null，流程自动降级为纯规则解析） */
    private AiService buildAiService() {
        AppConfig.AiEndpoint ep = cfg.useExternalAi ? cfg.externalAi : cfg.internalAi;
        AiClient client = new AiClient(ep.baseUrl, ep.apiKey, ep.model, ep.timeoutSec);
        if (!client.isConfigured()) {
            log(I18n.tag("log.tag.ai") + I18n.get("ai.notConfigured"));
            return null;
        }
        log(I18n.tag("log.tag.ai") + I18n.get("ai.usingModel", I18n.get(cfg.useExternalAi ? "ai.ext" : "ai.int"), ep.model));
        return new AiService(client);
    }

    private void startScan(boolean silentScan) {
        File root = validateScanTarget();
        if (root == null) return;
        saveCfg();
        progressBar.setIndeterminate(true);
        progressBar.setString(I18n.get("scan.progress"));
        setBusy(true);
        final AiService aiSvc = cfg.aiAnalyze ? buildAiService() : null;
        final File rootF = root;

        new SwingWorker<Void, String>() {
            @Override
            protected Void doInBackground() throws Exception {
                publish(I18n.tag("log.tag.scan") + I18n.get("log.scan.start", rootF.getAbsolutePath()));
                DependencyScanner.ScanResult sr = doScan(rootF, aiSvc, this::publish);
                lastDeps = sr.dependencies;
                lastAiAnalysis = sr.aiAnalysis;
                lastScannedFolder = rootF.getAbsolutePath();
                publish(I18n.tag("log.tag.excel") + I18n.get("log.excel.gen"));
                ExcelReport.write(new File(outputFile()), lastDeps, lastAiAnalysis, "");
                publish(I18n.tag("log.tag.excel") + I18n.get("log.excel.genDone", outputFile()));
                return null;
            }

            @Override
            protected void process(List<String> chunks) {
                for (String line : chunks) log(line);
            }

            @Override
            protected void done() {
                progressBar.setIndeterminate(false);
                progressBar.setString(I18n.get("scan.ready"));
                setBusy(false);
                try {
                    get();
                    if (!silentScan) {
                        JOptionPane.showMessageDialog(MainFrame.this,
                                I18n.get("dlg.scanDone.msg", lastDeps.size(), outputFile()),
                                I18n.get("dlg.scanDone.title"), JOptionPane.INFORMATION_MESSAGE);
                    }
                } catch (Exception e) {
                    log(I18n.tag("log.tag.err") + I18n.get("dlg.scanFail", e.getMessage()));
                    JOptionPane.showMessageDialog(MainFrame.this, I18n.get("dlg.scanFail", e.getMessage()),
                            I18n.get("dlg.error"), JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void startQuery(boolean forceRescan) {
        saveCfg();
        // 外部 Excel 清单模式：直接读取用户提供的组件清单（跳过代码文件夹扫描），并弹出组件选择框
        String listPath = excelListField.getText().trim();
        if (!listPath.isEmpty()) {
            File lf = new File(listPath);
            if (!lf.exists()) {
                JOptionPane.showMessageDialog(this, I18n.get("dlg.excelListNotExist", listPath));
                return;
            }
            startQueryFromExcel(lf);
            return;
        }
        File root = validateScanTarget();
        if (root == null) return;
        progressBar.setIndeterminate(true);
        progressBar.setString(I18n.get("scan.progress"));
        setBusy(true);
        final AiService aiSvc = buildAiService();
        final File rootF = root;
        final AppConfig cfgSnapshot = cfg;

        new SwingWorker<Void, String>() {
            @Override
            protected Void doInBackground() throws Exception {
                // 1. 扫描（若尚未扫描或对象变化）
                if (forceRescan || lastDeps.isEmpty() || !rootF.getAbsolutePath().equals(lastScannedFolder)) {
                    publish(I18n.tag("log.tag.scan") + I18n.get("log.scan.start", rootF.getAbsolutePath()));
                    DependencyScanner.ScanResult sr = doScan(rootF, aiSvc, this::publish);
                    lastDeps = sr.dependencies;
                    lastAiAnalysis = sr.aiAnalysis;
                    lastScannedFolder = rootF.getAbsolutePath();
                }
                return null;
            }

            @Override
            protected void process(List<String> chunks) {
                for (String line : chunks) log(line);
            }

            @Override
            protected void done() {
                try {
                    get();
                    queryAndReport(lastDeps, lastAiAnalysis, cfgSnapshot, aiSvc);
                } catch (Exception e) {
                    progressBar.setIndeterminate(false);
                    progressBar.setString(I18n.get("scan.ready"));
                    setBusy(false);
                    log(I18n.tag("log.tag.err") + I18n.get("dlg.scanFail", e.getMessage()));
                    JOptionPane.showMessageDialog(MainFrame.this,
                            I18n.get("dlg.scanFail", e.getMessage()), I18n.get("dlg.error"), JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    /** 外部 Excel 清单模式：读取组件清单 → 弹出组件选择框(默认全选) → 对勾选组件执行漏洞查询 */
    private void startQueryFromExcel(final File listFile) {
        final AppConfig cfgSnapshot = cfg;
        final AiService aiSvc = buildAiService();
        progressBar.setIndeterminate(true);
        progressBar.setString(I18n.get("scan.progressExcel"));
        setBusy(true);

        new SwingWorker<List<Dependency>, String>() {
            @Override
            protected List<Dependency> doInBackground() throws Exception {
                publish(I18n.tag("log.tag.excel") + I18n.get("log.excel.read", listFile.getAbsolutePath()));
                List<Dependency> deps = ExcelReport.readDependencies(listFile);
                publish(I18n.tag("log.tag.excel") + I18n.get("log.excel.readDone", deps.size()));
                return deps;
            }

            @Override
            protected void process(List<String> chunks) {
                for (String line : chunks) log(line);
            }

            @Override
            protected void done() {
                try {
                    List<Dependency> deps = get();
                    List<Dependency> selected = ComponentSelectDialog.showDialog(MainFrame.this, deps);
                    if (selected == null || selected.isEmpty()) {
                        log(I18n.tag("log.tag.query") + I18n.get("dlg.noSelect"));
                        progressBar.setIndeterminate(false);
                        progressBar.setString(I18n.get("scan.ready"));
                        setBusy(false);
                        return;
                    }
                    log(I18n.tag("log.tag.query") + I18n.get("dlg.selected", selected.size()));
                    lastDeps = selected;
                    lastAiAnalysis = "";
                    queryAndReport(selected, "", cfgSnapshot, aiSvc);
                } catch (Exception e) {
                    progressBar.setIndeterminate(false);
                    progressBar.setString(I18n.get("scan.ready"));
                    setBusy(false);
                    log(I18n.tag("log.tag.err") + I18n.get("dlg.excelReadFail", e.getMessage()));
                    JOptionPane.showMessageDialog(MainFrame.this,
                            I18n.get("dlg.excelReadFail", e.getMessage()), I18n.get("dlg.error"), JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    /** 公共查询流程：漏洞查询 → AI修复建议 → 回写Excel → 完成提示框 */
    private void queryAndReport(final List<Dependency> deps, final String aiAnalysis,
                                final AppConfig cfgSnapshot, final AiService aiSvc) {
        progressBar.setIndeterminate(true);
        progressBar.setString(I18n.get("scan.progressQuery"));
        setBusy(true);

        new SwingWorker<Void, String>() {
            @Override
            protected Void doInBackground() throws Exception {
                publish(I18n.tag("log.tag.query") + I18n.get("log.query.start", deps.size()));

                // 2. 漏洞查询
                CveQueryService service = new CveQueryService(cfgSnapshot);
                service.queryAll(deps, this::publish);

                // 3. AI 修复建议
                String fixReport = "";
                if (cfgSnapshot.aiFix && aiSvc != null) {
                    List<Dependency> vulnDeps = new ArrayList<Dependency>();
                    for (Dependency d : deps) {
                        if (d.isHasVuln()) vulnDeps.add(d);
                    }
                    if (!vulnDeps.isEmpty()) {
                        publish(I18n.tag("log.tag.ai") + I18n.get("log.fix.aiApplying", vulnDeps.size()));
                        List<AiService.FixSuggestion> fixes = aiSvc.suggestFixes(vulnDeps);
                        StringBuilder rep = new StringBuilder();
                        int applied = 0;
                        for (AiService.FixSuggestion f : fixes) {
                            rep.append(I18n.get("log.fix.aiLine", f.packageId,
                                    f.recommendedVersion.isEmpty() ? I18n.get("fix.none") : f.recommendedVersion,
                                    f.note.isEmpty() ? "" : " (" + f.note + ")"));
                            rep.append("\n");
                            for (Dependency d : deps) {
                                if (d.packageId.equals(f.packageId) && d.aiFixSuggestion.isEmpty()) {
                                    d.aiFixSuggestion = I18n.get("log.fix.aiApplied", f.recommendedVersion,
                                            f.note.isEmpty() ? "" : I18n.get("fix.noteSep") + f.note);
                                    applied++;
                                }
                            }
                        }
                        fixReport = rep.toString();
                        publish(I18n.tag("log.tag.ai") + I18n.get("log.fix.aiDone", applied));
                        // 记录修复建议获取日期（接口读取日期）
                        String today = new java.text.SimpleDateFormat("yyyy-MM-dd").format(new java.util.Date());
                        for (Dependency d : deps) {
                            if (!d.aiFixSuggestion.isEmpty() && d.fixSuggestionDate.isEmpty()) {
                                d.fixSuggestionDate = today;
                            }
                        }
                    }
                }

                // 4. 写 Excel
                publish(I18n.tag("log.tag.excel") + I18n.get("log.excel.write"));
                ExcelReport.write(new File(outputFile()), deps, aiAnalysis, fixReport);
                publish(I18n.tag("log.tag.excel") + I18n.get("log.excel.saved", outputFile()));
                return null;
            }

            @Override
            protected void process(List<String> chunks) {
                for (String line : chunks) log(line);
            }

            @Override
            protected void done() {
                progressBar.setIndeterminate(false);
                progressBar.setString(I18n.get("scan.ready"));
                setBusy(false);
                try {
                    get();
                    int vulnCount = 0;
                    for (Dependency d : deps) {
                        if (d.isHasVuln()) vulnCount++;
                    }
                    showCompleteDialog(deps.size(), vulnCount, outputFile());
                } catch (Exception e) {
                    log(I18n.tag("log.tag.err") + I18n.get("dlg.queryFail", e.getMessage()));
                    JOptionPane.showMessageDialog(MainFrame.this,
                            I18n.get("dlg.queryFail", e.getMessage()), I18n.get("dlg.error"), JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    /** 按当前扫描模式执行依赖扫描（代码项目 / lib文件夹 / jar-war包） */
    private DependencyScanner.ScanResult doScan(File target, AiService aiSvc, java.util.function.Consumer<String> log) {
        if (rbScanArchive.isSelected()) {
            return DependencyScanner.scanArchive(target, aiSvc, log);
        }
        if (rbScanLib.isSelected()) {
            return DependencyScanner.scanLibFolder(target, aiSvc, log);
        }
        return DependencyScanner.scan(target, aiSvc, log);
    }

    /** 分析完成提示框：可选择直接打开 Excel */
    private void showCompleteDialog(int total, int vulnCount, String file) {
        Object[] options = {I18n.get("dlg.openExcel"), I18n.get("dlg.openFolder"), I18n.get("dlg.close")};
        int choice = JOptionPane.showOptionDialog(this,
                I18n.get("dlg.complete.msg") + "\n\n"
                        + I18n.get("dlg.complete.summary", total, vulnCount) + "\n\n"
                        + I18n.get("dlg.complete.saved") + "\n" + file + "\n\n"
                        + I18n.get("dlg.complete.contains"),
                I18n.get("dlg.complete.title"), JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE,
                null, options, options[0]);
        if (choice == 0) {
            try {
                if (Desktop.isDesktopSupported()) Desktop.getDesktop().open(new File(file));
            } catch (Exception e) {
                log(I18n.tag("log.tag.err") + I18n.get("log.excel.openFail", e.getMessage()));
            }
        } else if (choice == 1) {
            try {
                File f = new File(file);
                if (Desktop.isDesktopSupported() && f.getParentFile() != null) {
                    Desktop.getDesktop().open(f.getParentFile());
                }
            } catch (Exception e) {
                log(I18n.tag("log.tag.err") + I18n.get("dlg.openFolderFail", e.getMessage()));
            }
        }
    }

    private File validateScanTarget() {
        String path = folderField.getText().trim();
        if (path.isEmpty()) {
            JOptionPane.showMessageDialog(this, I18n.get("scan.chooseFirst"));
            return null;
        }
        File f = new File(path);
        if (rbScanArchive.isSelected()) {
            if (!f.exists() || !f.isFile()) {
                JOptionPane.showMessageDialog(this, I18n.get("scan.fileNotExist", path));
                return null;
            }
        } else {
            if (!f.exists() || !f.isDirectory()) {
                JOptionPane.showMessageDialog(this, I18n.get("scan.folderNotExist", path));
                return null;
            }
        }
        return f;
    }

    private String outputFile() {
        String out = outputField.getText().trim();
        if (out.isEmpty()) {
            // 外部Excel清单模式下，默认输出到清单所在目录
            String listPath = excelListField.getText().trim();
            if (!listPath.isEmpty()) {
                File lf = new File(listPath);
                if (lf.getParentFile() != null) {
                    out = lf.getParentFile().getAbsolutePath() + File.separator + I18n.get("scan.defaultOutput");
                }
            }
            if (out.isEmpty()) {
                out = folderField.getText().trim() + File.separator + I18n.get("scan.defaultOutput");
            }
            outputField.setText(out);
        }
        if (!out.toLowerCase().endsWith(".xlsx")) out += ".xlsx";
        return out;
    }

    private void setBusy(boolean busy) {
        btnScan.setEnabled(!busy);
        btnQuery.setEnabled(!busy);
        btnOneClick.setEnabled(!busy);
        btnOpenExcel.setEnabled(!busy);
    }

    private void log(String line) {
        if (SwingUtilities.isEventDispatchThread()) {
            logArea.append("[" + new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date()) + "] " + line + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        } else {
            SwingUtilities.invokeLater(() -> log(line));
        }
    }
}
