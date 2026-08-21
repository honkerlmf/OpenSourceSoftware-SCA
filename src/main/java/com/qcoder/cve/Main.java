package com.qcoder.cve;

import com.qcoder.cve.ui.MainFrame;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/** 程序入口 */
public class Main {

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
        }
        SwingUtilities.invokeLater(() -> new MainFrame().setVisible(true));
    }
}
