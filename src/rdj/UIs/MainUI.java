package rdj.UIs;

import javafx.application.Platform;
import rdj.GUIFX;
import rdj.UI;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;

public class MainUI {
    private static MainUI mainUI;
    public GUIFX guifx;

    public static MainUI get(GUIFX guifx) {
        if (mainUI == null) mainUI = new MainUI(guifx);

        return mainUI;
    }

    public static MainUI get() {
        return mainUI;
    }

    protected MainUI(GUIFX guifx) {
        this.guifx = guifx;
    }


}
