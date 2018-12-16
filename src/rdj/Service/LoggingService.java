package rdj.Service;

import javafx.application.Platform;
import rdj.UIs.MainUI;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;

public class LoggingService {
    private static LoggingService loggingService;


    public static LoggingService get() {
        if (loggingService == null) loggingService = new LoggingService();

        return loggingService;
    }

    protected LoggingService() {
    }

    synchronized public void log(String message, boolean status, boolean log, boolean logfile, boolean errfile, boolean print) {
        if (status) {
            if (MainUI.get() != null && MainUI.get().guifx != null) MainUI.get().guifx.changeStatus(message);
        }
        if (log) {
            if (MainUI.get() != null && MainUI.get().guifx != null)
                MainUI.get().guifx.addLog(message);
            else System.out.println(message);
        }
        if (logfile) {
            logfile(message);
        }
        if (errfile) {
            errfile(message);
        }
        if (print) {
            errfile(message);
        }
    }

    public void logfile(String message) {
        Platform.runLater(() -> {
            try {
                Files.write(ConfigurationService.get().getLogFilePath(), message.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.SYNC);
            } catch (IOException ex) {
                log("Files.write(" + ConfigurationService.get().getLogFilePath() + ")..));", true, true, false, false, false);
            }
        });
    }

    public void errfile(String message) {
        Platform.runLater(() -> {
            try {
                Files.write(ConfigurationService.get().getErrFilePath(), message.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.SYNC);
            } catch (IOException ex) {
                log("Files.write(" + ConfigurationService.get().getErrFilePath() + ")..));", true, true, false, false, false);
            }
        });
    }
}
