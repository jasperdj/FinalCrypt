package rdj.Service;

import javafx.application.Platform;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.control.DialogPane;
import rdj.Util.ResourceUtil;
import rdj.Util.Time;

import java.awt.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

public class UpdateService {
    private static UpdateService updateService;

    private VersionService versionService;
    private LoggingService loggingService;
    private ConfigurationService configurationService;

    public static UpdateService get() {
        if (updateService == null) {
            updateService = new UpdateService();
        }

        return updateService;
    }

    protected UpdateService() {
        versionService = VersionService.get();
        loggingService = LoggingService.get();
        configurationService = ConfigurationService.get();
    }

    public void checkIfUpdateIsDue() {
        //	Last Update Checked
        long updateChecked = 0; // Epoch date
        //	long updateCheckPeriod = 1000L*20L; // Just to test auto update function
        long updateCheckPeriod = 1000L * 60L * 60L * 24L; // Update period 1 Day
        Time.updateNow(); // Epoch date
        String val = configurationService.getPrefs().get("Update Checked", "Unknown"); // if no val then "Unknown" prefs location registry: HKEY_CURRENT_USER\Software\JavaSoft\Prefs
        boolean invalidUpdateCheckedValue = false;
        try {
            updateChecked = Long.valueOf(val);
        } catch (NumberFormatException e) {
            invalidUpdateCheckedValue = true;
        }
        if (invalidUpdateCheckedValue) {
            checkUpdate();
        } else {
            if (Time.getNow() - updateChecked >= updateCheckPeriod) {
                checkUpdate();
            }
        }
    }

    public void checkUpdate() {
        Platform.runLater(() -> {
            String alertString = "";
            versionService.checkCurrentlyInstalledVersion();
            versionService.checkLatestOnlineVersion();
            configurationService.getPrefs().putLong("Update Checked", Time.getNow(true));
            String[] lines = versionService.getUpdateStatus().split("\r\n");
            for (String line : lines) {
                loggingService.log(line + "\r\n", true, true, true, false, false);
            }

            alertString = "Download new version: " + versionService.getLatestOnlineOverallVersionString() + "?\r\n\r\n";
            if (!versionService.getLatestReleaseNotesString().isEmpty()) {
                alertString += versionService.getLatestReleaseNotesString() + "\r\n";
            }
            if (!versionService.getLatestVersionMessageString().isEmpty()) {
                alertString += versionService.getLatestVersionMessageString() + "\r\n";
            }
            if ((!versionService.getLatestAlertSubjectString().isEmpty()) && (!versionService.getLatestAlertMessageString().isEmpty())) {
                Alert alert = new Alert(Alert.AlertType.INFORMATION);

                //      Style the Alert
                DialogPane dialogPane = alert.getDialogPane();
                dialogPane.getStylesheets().add(ResourceUtil.getResource("myInfoAlerts.css").toExternalForm());
                dialogPane.getStyleClass().add("myDialog");

                alert.setTitle("Information Dialog");
                alert.setHeaderText(versionService.getLatestAlertSubjectString() + "\r\n");
                alert.setResizable(true);
                alert.setContentText(versionService.getLatestAlertMessageString());
                alert.showAndWait();
            }
            if ((versionService.versionIsDifferent()) && (versionService.versionCanBeUpdated())) {
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION, alertString, ButtonType.YES, ButtonType.NO);
                alert.setHeaderText("Download Update?");
                alert.showAndWait();

                if (alert.getResult() == ButtonType.YES) {
                    Thread updateThread;
                    updateThread = new Thread(() ->
                    {
                        try {
                            try {
                                Desktop.getDesktop().browse(new URI(VersionService.REMOTEPACKAGEDOWNLOADURISTRING));
                            } catch (URISyntaxException ex) {
                                loggingService.log(ex.getMessage(), true, true, true, true, false);
                            }
                        } catch (IOException ex) {
                            loggingService.log(ex.getMessage(), true, true, true, true, false);
                        }
                    });
                    updateThread.setName("updateThread");
                    updateThread.setDaemon(true);
                    updateThread.start();
                }
            }
        });
    }
}

