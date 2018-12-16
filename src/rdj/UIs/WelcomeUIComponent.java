package rdj.UIs;

import javafx.application.Platform;
import javafx.scene.Group;
import javafx.scene.Node;
import javafx.scene.control.*;
import rdj.Service.ConfigurationService;
import rdj.Service.LoggingService;
import rdj.Service.VersionService;
import rdj.Util.ResourceUtil;

import java.util.function.Consumer;

public class WelcomeUIComponent {
    private ConfigurationService configurationService;
    private LoggingService loggingService;
    private VersionService versionService;
    private MainUI mainUI;


    public WelcomeUIComponent() {
        configurationService = ConfigurationService.get();
        loggingService = LoggingService.get();
        versionService = VersionService.get();
        mainUI = MainUI.get();
    }

    public void welcome() {


        Platform.runLater(() -> {
            String title = "Welcome to " + VersionService.getProduct();
            String header = "Brief Introduction:";
            String infotext = "";
            infotext += "Step 0 Optionally create an OTP key file below.\r\n";
            infotext += "Step 1 Select items to en/decrypt on the left.\r\n";
            infotext += "Step 2 Select your (OTP) key file on the right.\r\n";
            infotext += "Step 3 Click [Encrypt] / [Decrypt] button below.\r\n";
            infotext += "\r\n";
            infotext += "Optional:\r\n";
            infotext += "\r\n";
            infotext += "Double click to open files.\r\n";
            infotext += "Click [LOG] to see details.\r\n";
            infotext += "Click [Check Update] sometimes.\r\n";
            infotext += "Tip:  Watch statusbar at bottom.\r\n";
            infotext += "Tip:  Make backups of your data.\r\n";
            infotext += "Tip:  Keep your keys secret on external Storage.\r\n";
            infotext += "\r\n";
            infotext += "Live to love - Enjoy your privacy.\r\n\r\n";

            //	Hide Intro
            String val = configurationService.getPrefs().get("Hide Intro", "Unknown"); // if no val then "Unknown" prefs location registry: HKEY_CURRENT_USER\Software\JavaSoft\Prefs

            if (!val.equals("Yes")) {
                Alert alert = introAlert(Alert.AlertType.INFORMATION, title, header, infotext, "Don't show again", param -> configurationService.getPrefs().put("Hide Intro", param ? "Yes" : "No"), ButtonType.OK);
                if (alert.showAndWait().filter(t -> t == ButtonType.OK).isPresent()) {
                }
            }


        });
        Alert alert = new Alert(Alert.AlertType.INFORMATION);

        // Style the Alert
        DialogPane dialogPane = alert.getDialogPane();
        dialogPane.getStylesheets().add(ResourceUtil.getResource("myInfoAlerts.css").toExternalForm());
        dialogPane.getStyleClass().add("myDialog");
    }

    public Alert introAlert(Alert.AlertType type, String title, String headerText, String message, String optOutMessage, Consumer<Boolean> optOutAction, ButtonType... buttonTypes) {
        Alert alert = new Alert(type);
        alert.getDialogPane().applyCss();
        Node graphic = alert.getDialogPane().getGraphic();
        DialogPane dialogPane = new DialogPane() {
            @Override
            protected Node createDetailsButton() {
                CheckBox checkbox = new CheckBox();
                checkbox.setText(optOutMessage);
                checkbox.setOnAction(e -> optOutAction.accept(checkbox.isSelected()));
                return checkbox;
            }
        };
        dialogPane.getStylesheets().add(ResourceUtil.getResource("myInfoAlerts.css").toExternalForm());
        dialogPane.getStyleClass().add("myDialog");

        alert.setDialogPane(dialogPane);
        alert.getDialogPane().getButtonTypes().addAll(buttonTypes);
        alert.getDialogPane().setContentText(message);
        alert.getDialogPane().setExpandableContent(new Group());
        alert.getDialogPane().setExpanded(true);
        alert.getDialogPane().setGraphic(graphic);
        alert.setTitle(title);
        alert.setHeaderText(headerText);
        return alert;
    }
}