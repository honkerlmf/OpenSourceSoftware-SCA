package com.qcoder.cve.ui;

import com.qcoder.cve.i18n.I18n;
import com.qcoder.cve.model.Dependency;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 组件多选对话框：勾选需要查询漏洞的组件，默认全选，支持关键词筛选与全选/全不选。
 * 点击行即勾选/取消勾选；筛选只影响列表显示，确定时返回全部已勾选组件（含被筛选隐藏的）。
 */
public class ComponentSelectDialog extends JDialog {

    private final List<Dependency> allDeps;
    /** 已勾选集合（与筛选无关，保持对象引用一致） */
    private final Set<Dependency> checked = new HashSet<Dependency>();
    private final JTextField filterField = new JTextField();
    private final JList<Dependency> list = new JList<Dependency>(new DefaultListModel<Dependency>());
    private final JLabel countLabel = new JLabel();
    private List<Dependency> result = null;

    private ComponentSelectDialog(Component owner, List<Dependency> deps) {
        super((Frame) SwingUtilities.getWindowAncestor(owner), I18n.get("sel.title"), true);
        this.allDeps = new ArrayList<Dependency>(deps);
        checked.addAll(allDeps); // 默认全选

        list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        list.setCellRenderer(new CheckboxRenderer());
        list.addListSelectionListener(e -> {
            checked.clear();
            for (Dependency d : list.getSelectedValuesList()) checked.add(d);
            updateCount();
        });

        filterField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                applyFilter();
            }

            public void removeUpdate(DocumentEvent e) {
                applyFilter();
            }

            public void changedUpdate(DocumentEvent e) {
                applyFilter();
            }
        });

        JButton btnAll = new JButton(I18n.get("sel.all"));
        btnAll.addActionListener(e -> selectAll(true));
        JButton btnNone = new JButton(I18n.get("sel.none"));
        btnNone.addActionListener(e -> selectAll(false));
        JButton btnOk = new JButton(I18n.get("sel.ok"));
        btnOk.addActionListener(e -> {
            // 返回全部已勾选组件（按原清单顺序），不受筛选影响
            result = new ArrayList<Dependency>();
            for (Dependency d : allDeps) {
                if (checked.contains(d)) result.add(d);
            }
            dispose();
        });
        JButton btnCancel = new JButton(I18n.get("sel.cancel"));
        btnCancel.addActionListener(e -> dispose());

        JPanel top = new JPanel(new BorderLayout(6, 4));
        top.add(new JLabel(I18n.get("sel.filter")), BorderLayout.WEST);
        top.add(filterField, BorderLayout.CENTER);

        list.setVisibleRowCount(14);
        JScrollPane sp = new JScrollPane(list);

        JPanel bottom = new JPanel(new BorderLayout(6, 4));
        updateCount();
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        btns.add(btnAll);
        btns.add(btnNone);
        btns.add(btnOk);
        btns.add(btnCancel);
        bottom.add(countLabel, BorderLayout.WEST);
        bottom.add(btns, BorderLayout.EAST);

        setLayout(new BorderLayout(8, 8));
        add(top, BorderLayout.NORTH);
        add(sp, BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);
        setSize(700, 430);
        setLocationRelativeTo(owner);

        applyFilter(); // 初始展示全部并全选
    }

    /** 弹出模态对话框，返回勾选的组件列表；用户取消返回 null */
    public static List<Dependency> showDialog(Component owner, List<Dependency> deps) {
        ComponentSelectDialog dlg = new ComponentSelectDialog(owner, deps);
        dlg.setVisible(true);
        return dlg.result;
    }

    private void applyFilter() {
        String kw = filterField.getText().trim().toLowerCase();
        DefaultListModel<Dependency> model = new DefaultListModel<Dependency>();
        List<Dependency> filtered = new ArrayList<Dependency>();
        for (Dependency d : allDeps) {
            boolean match = kw.isEmpty()
                    || d.packageId.toLowerCase().contains(kw)
                    || d.version.toLowerCase().contains(kw)
                    || d.language.getLabel().toLowerCase().contains(kw)
                    || d.introduceType.toLowerCase().contains(kw);
            if (match) {
                model.addElement(d);
                filtered.add(d);
            }
        }
        list.setModel(model);
        // 恢复筛选前已勾选的状态
        List<Integer> sel = new ArrayList<Integer>();
        for (int i = 0; i < filtered.size(); i++) {
            if (checked.contains(filtered.get(i))) sel.add(i);
        }
        int[] idx = new int[sel.size()];
        for (int i = 0; i < sel.size(); i++) idx[i] = sel.get(i);
        list.setSelectedIndices(idx);
        updateCount();
    }

    private void selectAll(boolean select) {
        DefaultListModel<Dependency> model = (DefaultListModel<Dependency>) list.getModel();
        if (select) {
            int[] idx = new int[model.size()];
            for (int i = 0; i < model.size(); i++) idx[i] = i;
            list.setSelectedIndices(idx);
        } else {
            list.clearSelection();
        }
    }

    private void updateCount() {
        int shown = ((DefaultListModel<Dependency>) list.getModel()).size();
        countLabel.setText(I18n.get("sel.count", checked.size(), shown, allDeps.size()));
    }

    /** 行渲染：复选框 + 组件信息 */
    private static class CheckboxRenderer extends JCheckBox implements ListCellRenderer<Dependency> {
        @Override
        public Component getListCellRendererComponent(JList<? extends Dependency> jlist, Dependency d,
                                                       int index, boolean isSelected, boolean cellHasFocus) {
            setSelected(isSelected);
            setText(d.display() + "    " + I18n.get("sel.item", I18n.localizeValue(d.language.getLabel()), d.introduceType));
            setOpaque(true);
            setBackground(isSelected ? jlist.getSelectionBackground() : jlist.getBackground());
            setForeground(isSelected ? jlist.getSelectionForeground() : jlist.getForeground());
            return this;
        }
    }
}
