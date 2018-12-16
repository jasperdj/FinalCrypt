/*
 * Copyright © 2017 Ron de Jong (ronuitzaandam@gmail.com).
 *
 * This is free software; you can redistribute it
 * under the terms of the Creative Commons License
 * Creative Commons License: (CC BY-NC-ND 4.0) as published by
 * https://creativecommons.org/licenses/by-nc-nd/4.0/ ; either
 * version 4.0 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Creative Commons Attribution-NonCommercial-NoDerivatives 4.0
 * International Public License for more details.
 *
 * You should have received a copy of the Creative Commons
 * Public License License along with this software;
 */
package rdj.Service;

import rdj.Util.ResourceUtil;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;

import static java.nio.channels.Channels.newChannel;

import java.nio.channels.ReadableByteChannel;
import java.util.Calendar;

// Todo: Make singleton
public class VersionService {
    public static final String WEBSITEURISTRING = "https://sites.google.com/site/ronuitholland/home/finalcrypt";
    public static final String REMOTEPACKAGEDOWNLOADURISTRING = "https://github.com/ron-from-nl/FinalCrypt/releases/tag/latest/";
    public static final String[] REMOTEPACKAGEDOWNLOADURISTRINGARRAY = {
            "https://github.com/ron-from-nl/FinalCrypt/releases/tag/latest/"
            , "https://sourceforge.net/projects/finalcrypt/files/"
    };
    private static final String COMPANYNAME = "Private Person";
    private static final String PRODUCTNAME = "FinalCrypt";
    private static final String AUTHOR = "Ron de Jong";
    private static final String AUTHOREMAIL = "ronuitzaandam@gmail.com";
    private static final String LICENSE = "Creative Commons License: (CC BY-NC-ND 4.0)";
    private static final String COPYRIGHT = "© 2017-" + Calendar.getInstance().get(Calendar.YEAR);
    private static final String LOCALVERSIONFILEURLSTRING = "VERSION2";
    private static final String[] REMOTEVERSIONFILEURLSTRINGARRAY = {
            "https://raw.githubusercontent.com/ron-from-nl/FinalCrypt/master/src/rdj/VERSION2"
            , "https://sourceforge.net/p/finalcrypt/code/ci/master/tree/src/rdj/VERSION2?format=raw"
    };
    private static String currentOverallVersionString = "";
    private static int currentVersionTotal = 0;
    private static String localContent = "";
    private static String remoteContent = "";
    public int currentInstalledVersion;
    public int latestRemoteVersion;
    private String latestOverallVersionString = "";
    private int latestVersionTotal = 0;
    private InputStream istream = null;
    private URL remoteURL = null;
    private ReadableByteChannel currentVersionByteChannel = null;
    private ReadableByteChannel latestVersionByteChannel = null;
    private ByteBuffer byteBuffer;
    private boolean currentVersionIsKnown = false;
    private boolean latestVersionIsKnown = false;
    private boolean updateAvailable = false;
    private String[] localFields;
    private String[] localValues;
    private String[] remoteFields;
    private String[] remoteValues;
    private String latestReleaseNotesString;
    private String latestReleaseMessageString;
    private String latestAlertSubjectString;
    private String latestAlertMessageString;
    
    private static VersionService versionService;
    
    private LoggingService loggingService;

    public static VersionService get() {
        if (versionService == null) versionService = new VersionService();
        
        return versionService;
    }
    
    protected VersionService() {
        latestReleaseNotesString = "";
        latestReleaseMessageString = "";
        latestAlertSubjectString = "";
        latestAlertMessageString = "";
        
        loggingService = LoggingService.get();
    }

    public static String getCopyright() {
        return COPYRIGHT;
    }

    public static String getLicense() {
        return LICENSE;
    }

    public static String getAuthor() {
        return AUTHOR;
    }

    public static String getAuthorEmail() {
        return AUTHOREMAIL;
    }

    public static String getProduct() {
        return PRODUCTNAME;
    }

    public static String getCompany() {
        return COMPANYNAME;
    }

    synchronized public String checkCurrentlyInstalledVersion() {
        istream = ResourceUtil.getResourceAsStream(LOCALVERSIONFILEURLSTRING);

        // Read the local VERSION file
        currentOverallVersionString = "Unknown";
        currentVersionByteChannel = newChannel(istream);
        byteBuffer = ByteBuffer.allocate(1024);
        byteBuffer.clear();
        localContent = "";

        try {
            while (currentVersionByteChannel.read(byteBuffer) > 0) {
                byteBuffer.flip();
                while (byteBuffer.hasRemaining()) {
                    localContent += (char) byteBuffer.get();
                }
            }
        } catch (IOException ex) {
            loggingService.log("Error: VersionService.checkCurrentlyInstalledVersion IOException: Channel.read(..) " + ex.getMessage() + "\r\n", true, true, true, true, false);
        }

        try {
            currentVersionByteChannel.close();
        } catch (IOException ex) {
            loggingService.log("Error: VersionService.checkCurrentlyInstalledVersion IOException: Channel.close(..) " + ex.getMessage() + "\r\n", true, true, true, true, false);
        }

        String[] lines = localContent.split("\n"); // VERSION2 file was create on linux with unix newlines \n

        localFields = new String[lines.length];
        localValues = new String[lines.length];

        // Convert lines to fields array
        int c = 0;
        for (String line : lines) {
            localFields[c] = line.substring(line.indexOf("[") + 1, line.indexOf("]"));
            localValues[c] = line.substring(line.indexOf("{") + 1, line.lastIndexOf("}"));
            c++;
        }

        for (int x = 0; x < (localFields.length); x++) {
            if (localFields[x].toLowerCase().equals("Version".toLowerCase())) {
                currentOverallVersionString = localValues[x];
            }
        }

        String currentVersionString = currentOverallVersionString.substring(0, currentOverallVersionString.indexOf(".")).replaceAll("[^\\d]", "");
        String currentUpgradeString = currentOverallVersionString.substring(currentOverallVersionString.indexOf("."), currentOverallVersionString.lastIndexOf(".")).replaceAll("[^\\d]", "");
        String currentUpdateString = currentOverallVersionString.substring(currentOverallVersionString.lastIndexOf("."), currentOverallVersionString.length()).replaceAll("[^\\d]", "");
        currentInstalledVersion = Integer.parseInt(currentVersionString);
        int currentUpgrade = Integer.parseInt(currentUpgradeString);
        int currentUpdate = Integer.parseInt(currentUpdateString);
        currentVersionTotal = (currentInstalledVersion * 100) + (currentUpgrade * 10) + (currentUpdate * 1);
        currentOverallVersionString = currentVersionString + "." + currentUpgradeString + "." + currentUpdateString;
        currentVersionIsKnown = true;

        return currentOverallVersionString;
    }

    synchronized public String checkLatestOnlineVersion() {
        // Read the remote VERSION file
        latestVersionIsKnown = false;
        latestOverallVersionString = "Unknown";


        for (String REMOTEVERSIONFILEURLSTRING : REMOTEVERSIONFILEURLSTRINGARRAY) {
            boolean failed = false;
            byteBuffer = ByteBuffer.allocate(1024);
            byteBuffer.clear();
            remoteContent = "";
            loggingService.log("Checking: " + REMOTEVERSIONFILEURLSTRING + "\r\n", false, false, true, false, false);

            try {
                remoteURL = new URL(REMOTEVERSIONFILEURLSTRING);
            } catch (MalformedURLException ex) {
                loggingService.log("Error: VersionService.checkLatestOnlineVersion MalformedURLException: new URL(" + REMOTEVERSIONFILEURLSTRING + ") (URL Typo?)\r\n", false, true, true, true, false);
                failed = true;
                continue;
            }

            try {
                latestVersionByteChannel = Channels.newChannel(remoteURL.openStream());
            } catch (IOException ex) {
                loggingService.log("Error: VersionService.checkLatestOnlineVersion IOException: Channels.newChannel(\"" + REMOTEVERSIONFILEURLSTRING + "\".openStream()) (file exist?)\r\n", false, true, true, true, false);
                failed = true;
                continue;
            } finally {
            } // null pointer at no connect

            try {
                while (latestVersionByteChannel.read(byteBuffer) > 0) {
                    byteBuffer.flip();
                    while (byteBuffer.hasRemaining()) {
                        remoteContent += (char) byteBuffer.get();
                    }
                }
            } catch (IOException ex) {
                loggingService.log("Error: VersionService.checkLatestOnlineVersion IOException: Channels.read(..) " + ex.getMessage() + "\r\n", false, true, true, true, false);
                failed = true;
                continue;
            }

            try {
                latestVersionByteChannel.close();
            } catch (IOException ex) {
                loggingService.log("Error: VersionService.checkLatestOnlineVersion IOException: Channels.close(..)  " + ex.getMessage() + "\r\n", false, true, true, true, false);
                continue;
            }

            if (!failed) {
                String[] lines = remoteContent.split("\n"); // VERSION2 file was create on linux with unix newlines \n

                remoteFields = new String[lines.length];
                remoteValues = new String[lines.length];

                //	    Convert lines to fields array
                int c = 0;
                for (String line : lines) {
                    remoteFields[c] = line.substring(line.indexOf("[") + 1, line.indexOf("]"));
                    remoteValues[c] = line.substring(line.indexOf("{") + 1, line.lastIndexOf("}"));
                    c++;
                }
                for (int x = 0; x < (remoteFields.length); x++) {
                    if (remoteFields[x].toLowerCase().equals("Version".toLowerCase())) {
                        latestOverallVersionString = remoteValues[x];
                    }
                    if (remoteFields[x].toLowerCase().equals("Release Notes".toLowerCase())) {
                        latestReleaseNotesString = remoteValues[x];
                    }
                    if (remoteFields[x].toLowerCase().equals("Release Message".toLowerCase())) {
                        latestReleaseMessageString = remoteValues[x];
                    }
                    if (remoteFields[x].toLowerCase().equals("Alert Subject".toLowerCase())) {
                        latestAlertSubjectString = remoteValues[x];
                    }
                    if (remoteFields[x].toLowerCase().equals("Alert Message".toLowerCase())) {
                        latestAlertMessageString = remoteValues[x];
                    }
                }

                String latestVersionString = latestOverallVersionString.substring(0, latestOverallVersionString.indexOf(".")).replaceAll("[^\\d]", "");
                String latestUpgradeString = latestOverallVersionString.substring(latestOverallVersionString.indexOf("."), latestOverallVersionString.lastIndexOf(".")).replaceAll("[^\\d]", "");
                String latestUpdateString = latestOverallVersionString.substring(latestOverallVersionString.lastIndexOf("."), latestOverallVersionString.length()).replaceAll("[^\\d]", "");
                latestRemoteVersion = Integer.parseInt(latestVersionString);
                int latestUpgrade = Integer.parseInt(latestUpgradeString);
                int latestUpdate = Integer.parseInt(latestUpdateString);
                latestVersionTotal = (latestRemoteVersion * 100) + (latestUpgrade * 10) + (latestUpdate * 1);
                latestOverallVersionString = latestVersionString + "." + latestUpgradeString + "." + latestUpdateString;
                latestVersionIsKnown = true;

                return latestOverallVersionString;
            }
            break;

        }
        return "Could not check for new updates (Internet?)";
    }

    public String getLatestOnlineOverallVersionString() {
        return latestOverallVersionString;
    }

    public String getCurrentlyInstalledOverallVersionString() {
        return currentOverallVersionString;
    }

    public String getLatestReleaseNotesString() {
        return latestReleaseNotesString;
    }

    public String getLatestVersionMessageString() {
        return latestReleaseMessageString;
    }

    public String getLatestAlertSubjectString() {
        return latestAlertSubjectString;
    }

    public String getLatestAlertMessageString() {
        return latestAlertMessageString;
    }

    public String getUpdateStatus() {
        String returnString = "";
        if ((currentVersionIsKnown) && (latestVersionIsKnown)) {
            if (currentVersionTotal < latestVersionTotal) {
                returnString += getProduct() + " " + currentOverallVersionString + " can be updated to version: " + latestOverallVersionString + " at: " + REMOTEPACKAGEDOWNLOADURISTRING + "\r\n";
                if (!getLatestReleaseNotesString().isEmpty()) {
                    returnString += getLatestReleaseNotesString() + "\r\n";
                }
                if (!getLatestVersionMessageString().isEmpty()) {
                    returnString += getLatestVersionMessageString() + "\r\n";
                }
            } else if (currentVersionTotal > latestVersionTotal) {
                returnString += getProduct() + " " + currentOverallVersionString + " is a development version!\r\n";
            } else {
                returnString += getProduct() + " " + currentOverallVersionString + " is up to date\r\n";
            }
        } else {
            if (!currentVersionIsKnown) {
                returnString = "Could not retrieve the locally installed " + VersionService.getProduct() + " Version\r\n";
            }
            if (!latestVersionIsKnown) {
                returnString = "Could not retrieve the latest online " + VersionService.getProduct() + " Version\r\n";
            }
        }
        return returnString;
    }

    public boolean versionIsDifferent() {
        if (currentVersionTotal != latestVersionTotal) {
            return true;
        } else {
            return false;
        }
    }

    public boolean versionCanBeUpdated() {
        if (currentVersionTotal < latestVersionTotal) {
            return true;
        } else {
            return false;
        }
    }

    public boolean versionIsDevelopment() {
        if (currentVersionTotal > latestVersionTotal) {
            return true;
        } else {
            return false;
        }
    }
}
