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

package rdj;

import rdj.Service.ConfigurationService;
import rdj.Service.LoggingService;
import rdj.Service.VersionService;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Scanner;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static rdj.GUIFX.getHexString;

/* commandline test routine

clear; echo -n -e \\x05 > 1; echo -n -e \\x03 > 2; java -jar FinalCrypt.jar
clear; echo -n -e \\x05 > 1; echo -n -e \\x03 > 2; java -cp FinalCrypt.jar rdj/CLUI --encrypt --print -k 2 -t 1
clear; echo -n ZYXVWUTSRQPONMLKJIHGFEDCBA098765 > a; echo -n abcdefghijklstuvwxyz > b; java -cp FinalCrypt.jar rdj/CLUI --print -k b -t a

*/

public class CLUI {
    private final ConfigurationService configurationService;
    private FinalCrypt finalCrypt;
    private VersionService versionService;
    private LoggingService loggingService;
    private boolean symlink = false;
    private boolean verbose = false;

    private boolean encrypt = false;
    private boolean decrypt = false;
    private boolean createkeydev = false;
    private boolean createkeyfile = false;
    private boolean clonekeydev = false;
    private boolean key_checksum = false;
    private boolean printgpt = false;
    private boolean deletegpt = false;

    private FCPathList encryptableList;
    private FCPathList decryptableList;
    private FCPathList createKeyList;
    private FCPathList cloneKeyList;

    private boolean encryptablesFound = false;
    private boolean decryptablesFound = false;
    private boolean createKeyDeviceFound = false;
    private boolean cloneKeyDeviceFound = false;
    private FCPathList printGPTTargetList;
    private boolean printGPTDeviceFound;
    private boolean deleteGPTDeviceFound;
    private FCPathList deleteGPTTargetList;
    private FCPathList targetFCPathList;
    private boolean keySourceChecksumReadEnded = false;
    private int bufferSize;
    private Long totalTranfered;
    private Long filesizeInBytes = 100L * (1024L * 1024L);  // Create OTP Key File Size
    private Path keyPath;
    private boolean encryptModeNeeded;

    private TimeoutThread timeoutThread;
    private ReaderThread readerThread;

    public CLUI(String[] args) {
        loggingService = LoggingService.get();

        boolean tfset = false;
        boolean tfsetneeded = false;
        boolean kfset = false;
        boolean kfsetneeded = true;
        boolean validInvocation = true;
        boolean negatePattern = false;

        ArrayList<Path> targetPathList = new ArrayList<>();
        ArrayList<Path> extendedTargetPathList = new ArrayList<>();
        Path batchFilePath = null;

        FCPath keyFCPath = null;

        Path outputFilePath = null;
        configurationService = ConfigurationService.get();
        versionService = VersionService.get();
        versionService.checkCurrentlyInstalledVersion();

        String pattern = "glob:*";

        // Load the FinalCrypt Objext
        finalCrypt = new FinalCrypt();
        finalCrypt.start();
        finalCrypt.setBufferSize(finalCrypt.getBufferSizeDefault());

        // Validate Parameters
        if (args.length == 0) {
            loggingService.log("\r\nError: No parameters entered!\r\n", false, true, true, true, false);
            usagePrompt(true);
        }

        for (int paramCnt = 0; paramCnt < args.length; paramCnt++) {
//          Options
            if ((args[paramCnt].equals("-h")) || (args[paramCnt].equals("--help"))) {
                usage(false);
            } else if (args[paramCnt].equals("--examples")) {
                examples();
            } else if (args[paramCnt].equals("--disable-MAC")) {
                finalCrypt.disableMAC = true;
                encryptModeNeeded = true;
            } else if (args[paramCnt].equals("--encrypt")) {
                if ((!encrypt) && (!decrypt) && (!createkeydev) && (!clonekeydev) && (!printgpt) && (!deletegpt)) {
                    encrypt = true;
                    kfsetneeded = true;
                    tfsetneeded = true;
                }
            } else if (args[paramCnt].equals("--decrypt")) {
                if ((!encrypt) && (!decrypt) && (!createkeydev) && (!clonekeydev) && (!printgpt) && (!deletegpt)) {
                    decrypt = true;
                    kfsetneeded = true;
                    tfsetneeded = true;
                }
            } else if (args[paramCnt].equals("--create-keydev")) {
                if ((!encrypt) && (!decrypt) && (!createkeydev) && (!clonekeydev) && (!printgpt) && (!deletegpt)) {
                    createkeydev = true;
                    kfsetneeded = true;
                    tfsetneeded = true;
                }
            } else if (args[paramCnt].equals("--create-keyfile")) {
                if ((!encrypt) && (!decrypt) && (!createkeydev) && (!clonekeydev) && (!printgpt) && (!deletegpt)) {
                    createkeyfile = true;
                    kfsetneeded = false;
                    tfsetneeded = false;
                }
            } else if (args[paramCnt].equals("--clone-keydev")) {
                if ((!encrypt) && (!decrypt) && (!createkeydev) && (!clonekeydev) && (!printgpt) && (!deletegpt)) {
                    clonekeydev = true;
                    kfsetneeded = true;
                    tfsetneeded = true;
                }
            } else if ((args[paramCnt].equals("--print"))) {
                finalCrypt.setPrint(true);
            } else if ((args[paramCnt].equals("--key-chksum"))) {
                key_checksum = true;
                kfsetneeded = true;
            } else if (args[paramCnt].equals("--print-gpt")) {
                if ((!encrypt) && (!decrypt) && (!createkeydev) && (!clonekeydev) && (!printgpt) && (!deletegpt)) {
                    printgpt = true;
                    kfsetneeded = false;
                    tfsetneeded = true;
                }
            } else if (args[paramCnt].equals("--delete-gpt")) {
                if ((!encrypt) && (!decrypt) && (!createkeydev) && (!clonekeydev) && (!printgpt) && (!deletegpt)) {
                    deletegpt = true;
                    kfsetneeded = false;
                    tfsetneeded = true;
                }
            } else if ((args[paramCnt].equals("-v")) || (args[paramCnt].equals("--verbose"))) {
                finalCrypt.setVerbose(true);
                verbose = true;
            } else if ((args[paramCnt].equals("-p")) || (args[paramCnt].equals("--print"))) {
                finalCrypt.setPrint(true);
            } else if ((args[paramCnt].equals("-l")) || (args[paramCnt].equals("--symlink"))) {
                finalCrypt.setSymlink(true);
                symlink = true;
            } else if (args[paramCnt].equals("--version")) {
                loggingService.log(versionService.getProduct() + " " + versionService.getCurrentlyInstalledOverallVersionString() + "\r\n", false, true, true, false, false);
                System.exit(0);
            } else if (args[paramCnt].equals("--license")) {
                loggingService.log(versionService.getProduct() + " " + VersionService.getLicense() + "\r\n", false, true, true, false, false);
                System.exit(0);
            } else if (args[paramCnt].equals("--check-update")) {
                versionService.checkLatestOnlineVersion();
                String[] lines = versionService.getUpdateStatus().split("\r\n");
                for (String line : lines) {
                    loggingService.log(line + "\r\n", false, true, true, false, false);
                }
                System.exit(0);
            } else if ((args[paramCnt].equals("-s")) && (!args[paramCnt + 1].isEmpty())) {
                if (validateIntegerString(args[paramCnt + 1])) {
                    finalCrypt.setBufferSize(Integer.valueOf(args[paramCnt + 1]) * 1024);
                    paramCnt++;
                } else {
                    loggingService.log("\r\nError: Invalid Option Value [-b size]" + "\r\n", false, true, true, true, false);
                    usagePrompt(true);
                }
            } else if ((args[paramCnt].equals("-S")) && (!args[paramCnt + 1].isEmpty())) {
                if (validateIntegerString(args[paramCnt + 1])) {
                    filesizeInBytes = Long.valueOf(args[paramCnt + 1]);
                    paramCnt++;
                } else {
                    loggingService.log("\r\nError: Invalid Option Value [-S size]" + "\r\n", false, true, true, true, false);
                    usagePrompt(true);
                }
            }

//          Filtering Options
            else if (args[paramCnt].equals("--dry")) {
                finalCrypt.setDry(true);
            } else if ((args[paramCnt].equals("-w")) && (!args[paramCnt + 1].isEmpty())) {
                negatePattern = false;
                pattern = "glob:" + args[paramCnt + 1];
                paramCnt++;
            } else if ((args[paramCnt].equals("-W")) && (!args[paramCnt + 1].isEmpty())) {
                negatePattern = true;
                pattern = "glob:" + args[paramCnt + 1];
                paramCnt++;
            } else if ((args[paramCnt].equals("-r")) && (!args[paramCnt + 1].isEmpty())) {
                pattern = "regex:" + args[paramCnt + 1];
                paramCnt++;
            }

//          File Parameters
            else if ((args[paramCnt].equals("-k")) && (paramCnt + 1 < args.length)) {
                keyFCPath = Validate.getFCPath("", Paths.get(args[paramCnt + 1]), true, Paths.get(args[paramCnt + 1]), true);
                kfset = true;
                paramCnt++;
            } else if ((args[paramCnt].equals("-K")) && (!args[paramCnt + 1].isEmpty())) {
                keyPath = Paths.get(args[paramCnt + 1]);
                paramCnt++;
            } // Create OTP Key File
            else if ((args[paramCnt].equals("-t")) && (!args[paramCnt + 1].isEmpty())) {
                targetPathList.add(Paths.get(args[paramCnt + 1]));
                tfset = true;
                paramCnt++;
            } else if ((args[paramCnt].equals("-b")) && (!args[paramCnt + 1].isEmpty())) {
                tfset = addBatchTargetFiles(args[paramCnt + 1], targetPathList);
                paramCnt++;
            } else {
                loggingService.log("\r\nError: Invalid Parameter: " + args[paramCnt] + "\r\n", false, true, true, true, false);
                usagePrompt(true);
            }
        }

        if ((encryptModeNeeded) && (decrypt)) {
            loggingService.log("\r\nError: MAC Mode Disabled! Use --encrypt if you know what you are doing!!!\r\n", false, true, true, true, false);
            usagePrompt(true);
        }
        if ((encryptModeNeeded) && (!encrypt)) {
            loggingService.log("\r\nError: Missing valid parameter <--encrypt>" + "\r\n", false, true, true, true, false);
            usagePrompt(true);
        }
        if ((kfsetneeded) && (!kfset)) {
            loggingService.log("\r\nError: Missing valid parameter <-k \"keyfile\">" + "\r\n", false, true, true, true, false);
            usagePrompt(true);
        }
        if ((tfsetneeded) && (!tfset)) {
            loggingService.log("\r\nError: Missing valid parameter <-t \"file/dir\"> or <-b \"batchfile\">" + "\r\n", false, true, true, true, false);
            usagePrompt(true);
        }


//////////////////////////////////////////////////// VALIDATE SELECTION /////////////////////////////////////////////////

        // Key Validation
        if ((kfsetneeded) && (!keyFCPath.isValidKey)) {
            String size = "";
            if (keyFCPath.size < FCPath.KEY_SIZE_MIN) {
                size += " [size < " + FCPath.KEY_SIZE_MIN + "] ";
            }
            String dir = "";
            if (keyFCPath.type == FCPath.DIRECTORY) {
                dir += " [is dir] ";
            }
            String sym = "";
            if (keyFCPath.type == FCPath.SYMLINK) {
                sym += " [is symlink] ";
            }
            String all = size + dir + sym;

            loggingService.log("\r\nKey parameter: -k \"" + keyFCPath.path + "\" Invalid:" + all + "\r\n\r\n", false, true, true, true, false);
            loggingService.log(Validate.getFCPathStatus(keyFCPath), false, true, false, false, false);
            usagePrompt(true);
        }

        // Target Validation

        if (tfsetneeded) {
            for (Path targetPath : targetPathList) {
                if (Files.exists(targetPath)) {
                    //			      isValidDir(UI ui, Path targetDirPath, boolean symlink, boolean report)
                    if (Validate.isValidDir(targetPath, symlink, verbose)) {
                        if (verbose) {
                            loggingService.log("Target parameter: " + targetPath + " is a valid dir\r\n", false, true, true, false, false);
                        }
                    }
                    //				   isValidFile(UI ui, String caller, Path targetSourcePath,  isKey, boolean device, long minSize, boolean symlink, boolean writable, boolean report)
                    else if (Validate.isValidFile("CLUI.CLUI() ", targetPath, false, false, 1L, symlink, true, verbose)) {
                        if (verbose) {
                            loggingService.log("Target parameter: " + targetPath + " is a valid file\r\n", false, true, true, false, false);
                        }
                    }
                } else {
                    loggingService.log("Target parameter: -t \"" + targetPath + "\" does not exists\r\n", false, true, true, true, false);
                    usagePrompt(true);
                }
            }
        }

//	Command line input for an optional Password keyboard.nextInt();


//	====================================================================================================================
//	 Start writing OTP key file
//	====================================================================================================================


        if (createkeyfile) {
            Long factor = 0L;
            bufferSize = 1048576;
            totalTranfered = 0L;


            if (Files.exists(keyPath, LinkOption.NOFOLLOW_LINKS)) {
                loggingService.log("Warning: file: \"" + keyPath.toAbsolutePath().toString() + "\" exists! Aborted!\r\n\r\n", false, true, false, false, false);
                System.exit(1);
            } else {
                loggingService.log("Creating OTP Key File" + " (" + Validate.getHumanSize(filesizeInBytes, 1) + ")...", false, true, false, false, false);
            }

            if (filesizeInBytes < bufferSize) {
                bufferSize = filesizeInBytes.intValue();
            }

            boolean inputEnded = false;
            long writeKeyFileChannelPosition = 0L;
            long writeKeyFileChannelTransfered = 0L;
            totalTranfered = 0L;
            Long remainder = 0L;

//	    Write the keyfile to 1st partition

            byte[] randomBytes1 = new byte[bufferSize];
            byte[] randomBytes2 = new byte[bufferSize];
            byte[] randomBytes3 = new byte[bufferSize];
            ByteBuffer randomBuffer1 = ByteBuffer.allocate(bufferSize);
            randomBuffer1.clear();
            ByteBuffer randomBuffer2 = ByteBuffer.allocate(bufferSize);
            randomBuffer2.clear();
            ByteBuffer randomBuffer3 = ByteBuffer.allocate(bufferSize);
            randomBuffer3.clear();


            SecureRandom random = new SecureRandom();

            write1loop:
            while ((totalTranfered < filesizeInBytes) && (!inputEnded)) {
                remainder = (filesizeInBytes - totalTranfered);

                if (remainder >= bufferSize) {
                    randomBytes1 = new byte[bufferSize];
                    randomBytes2 = new byte[bufferSize];
                    randomBytes3 = new byte[bufferSize];
                    randomBuffer1 = ByteBuffer.allocate(bufferSize);
                    randomBuffer1.clear();
                    randomBuffer2 = ByteBuffer.allocate(bufferSize);
                    randomBuffer2.clear();
                    randomBuffer3 = ByteBuffer.allocate(bufferSize);
                    randomBuffer3.clear();
                } else if ((remainder > 0) && (remainder < bufferSize)) {
                    randomBytes1 = new byte[remainder.intValue()];
                    randomBytes2 = new byte[remainder.intValue()];
                    randomBytes3 = new byte[remainder.intValue()];
                    randomBuffer1 = ByteBuffer.allocate(remainder.intValue());
                    randomBuffer1.clear();
                    randomBuffer2 = ByteBuffer.allocate(remainder.intValue());
                    randomBuffer2.clear();
                    randomBuffer3 = ByteBuffer.allocate(remainder.intValue());
                    randomBuffer3.clear();
                } else {
                    inputEnded = true;
                }
//              Randomize raw key or write raw key straight to partition
                random.nextBytes(randomBytes1);
                randomBuffer1.put(randomBytes1);
                randomBuffer1.flip();
                random.nextBytes(randomBytes2);
                randomBuffer2.put(randomBytes2);
                randomBuffer2.flip();

                randomBuffer3 = FinalCrypt.encryptBuffer(randomBuffer1, randomBuffer2, false); // Encrypt

//              Write Device
                try (final SeekableByteChannel writeKeyFileChannel = Files.newByteChannel(keyPath, EnumSet.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.SYNC))) {
                    writeKeyFileChannel.position(writeKeyFileChannelPosition);
                    writeKeyFileChannelTransfered = writeKeyFileChannel.write(randomBuffer3);
                    randomBuffer3.rewind();
                    totalTranfered += writeKeyFileChannelTransfered;
//		    loggingService.log("tot: " + filesizeInBytes + " trans: " + totalTranfered + " remain: " + remainder + " p: " + (double)totalTranfered / filesizeInBytes + "\r\n", false, true, false, false, false);

                    writeKeyFileChannelPosition += writeKeyFileChannelTransfered;

                    writeKeyFileChannel.close();
                } catch (IOException ex) {
                    loggingService.log("\r\nError: " + ex.getMessage() + "\r\n", false, true, true, true, false);
                    inputEnded = true;
                    break;
                }
                randomBuffer1.clear();
                randomBuffer2.clear();
                randomBuffer3.clear();
            }
            writeKeyFileChannelPosition = 0;
            writeKeyFileChannelTransfered = 0;
            inputEnded = false;


            loggingService.log("finished\r\n", false, true, false, false, false);
            System.exit(0);
        }

//	====================================================================================================================
//	Finieshed writing key file
//	====================================================================================================================


//////////////////////////////////////////////////// KEY CHECKSUM =====================================================

        if (key_checksum) {
            loggingService.log("\r\nKey CheckSum: (SHA-1): \"" + keyFCPath.path.toAbsolutePath().toString() + "\"...\r\n", false, true, false, false, false);
            long readKeySourceChannelPosition = 0;
            long readKeySourceChannelTransfered = 0;
            int readKeySourceBufferSize = (1 * 1024 * 1024);
            ByteBuffer keySourceBuffer = ByteBuffer.allocate(readKeySourceBufferSize);
            keySourceBuffer.clear();
            MessageDigest messageDigest = null;
            try {
                messageDigest = MessageDigest.getInstance("SHA-1");
            } catch (NoSuchAlgorithmException ex) {
                loggingService.log("Error: NoSuchAlgorithmException: MessageDigest.getInstance(\"SHA-256\")\r\n", false, true, true, true, false);
            }
            int x = 0;
            while (!keySourceChecksumReadEnded) {
                try (final SeekableByteChannel readKeySourceChannel = Files.newByteChannel(keyFCPath.path, EnumSet.of(StandardOpenOption.READ, StandardOpenOption.SYNC))) {
                    readKeySourceChannel.position(readKeySourceChannelPosition);
                    readKeySourceChannelTransfered = readKeySourceChannel.read(keySourceBuffer);
                    keySourceBuffer.flip();
                    readKeySourceChannelPosition += readKeySourceChannelTransfered;
                    readKeySourceChannel.close();

                    messageDigest.update(keySourceBuffer);
                    if (readKeySourceChannelTransfered < 0) {
                        keySourceChecksumReadEnded = true;
                    }
                } catch (IOException ex) {
                    keySourceChecksumReadEnded = true;
                    loggingService.log("readKeySourceChannel = Files.newByteChannel(..) " + ex.getMessage() + "\r\n", false, true, false, false, false);
                }
                x++;
                keySourceBuffer.clear();
            }
            byte[] hashBytes = messageDigest.digest();
            String hashString = getHexString(hashBytes, 2);
            loggingService.log("Message Digest:         " + hashString + "\r\n\r\n", false, true, false, false, false);
        }


//////////////////////////////////////////////////// BUILD SELECTION /////////////////////////////////////////////////

        targetFCPathList = new FCPathList();
        if (!kfsetneeded) {
            keyFCPath = Validate.getFCPath("", targetPathList.get(0), false, targetPathList.get(0), true);
        }
        Validate.buildSelection(targetPathList, keyFCPath, targetFCPathList, symlink, pattern, negatePattern, false);

/////////////////////////////////////////////// SET BUILD MODES ////////////////////////////////////////////////////

        if ((keyFCPath != null) && (keyFCPath.isValidKey)) {
//	    loggingService.log(targetFCPathList.getStats());
            // Encryptables
            if (targetFCPathList.encryptableFiles > 0) {
                encryptableList = filter(targetFCPathList, (FCPath fcPath) -> fcPath.isEncryptable); // loggingService.log("Encryptable List:\r\n" + encryptableList.getStats());
                encryptablesFound = true;
            }

            // Encryptables
            if (targetFCPathList.decryptableFiles > 0) {
                decryptableList = filter(targetFCPathList, (FCPath fcPath) -> fcPath.isDecryptable); // loggingService.log("Decryptable List:\r\n" + decryptableList.getStats());
                decryptablesFound = true;
            }

            // Create Key Device
            if (keyFCPath.type == FCPath.FILE) {
                if (targetFCPathList.validDevices > 0) {
                    createKeyList = filter(targetFCPathList, (FCPath fcPath) -> fcPath.type == FCPath.DEVICE); // loggingService.log("Create Key List:\r\n" + createKeyList.getStats());
                    createKeyDeviceFound = true;
                } else {
                    createKeyDeviceFound = false;
                }
            } else if (keyFCPath.type == FCPath.DEVICE) {
                // Clone Key Device
                if ((targetFCPathList.validDevices > 0) && (targetFCPathList.matchingKey == 0)) {
                    final FCPath keyFCPath2 = keyFCPath; // for Lambda expression
                    cloneKeyList = filter(targetFCPathList, (FCPath fcPath) -> fcPath.type == FCPath.DEVICE && fcPath.path.compareTo(keyFCPath2.path) != 0); // loggingService.log("Clone Key List:\r\n" + cloneKeyList.getStats());
                    cloneKeyDeviceFound = true;
                } else {
                    cloneKeyDeviceFound = false;
                }
            } else {
                cloneKeyDeviceFound = false;
            }
        } else {
            createKeyDeviceFound = false;
        }

        if ((printgpt) && ((targetFCPathList.validDevices > 0) || (targetFCPathList.validDevicesProtected > 0))) {
            printGPTTargetList = filter(targetFCPathList, (FCPath fcPath) -> fcPath.type == FCPath.DEVICE || fcPath.type == FCPath.DEVICE_PROTECTED); // loggingService.log("Create Key List:\r\n" + createKeyList.getStats());
            printGPTDeviceFound = true;
        } else {
            printGPTDeviceFound = false;
        }

        if ((deletegpt) && (targetFCPathList.validDevices > 0)) {
            deleteGPTTargetList = filter(targetFCPathList, (FCPath fcPath) -> fcPath.type == FCPath.DEVICE); // loggingService.log("Create Key List:\r\n" + createKeyList.getStats());
            if (deleteGPTTargetList.size() > 0) {
                deleteGPTDeviceFound = true;
            } else {
                deleteGPTDeviceFound = false;
            }
        } else if ((deletegpt) && (targetFCPathList.validDevicesProtected > 0)) {
            deleteGPTTargetList = filter(targetFCPathList, (FCPath fcPath) -> fcPath.type == FCPath.DEVICE_PROTECTED); // loggingService.log("Create Key List:\r\n" + createKeyList.getStats());
            FCPath fcPath = (FCPath) deleteGPTTargetList.get(0);
            loggingService.log("WARNING: Device: " + fcPath.path + " is protected!!!\r\n", false, true, true, true, false);
            deleteGPTDeviceFound = false;
        } else {
            deleteGPTDeviceFound = false;
        }


/////////////////////////////////////////////// FINAL VALIDATION & EXECUTE MODES ////////////////////////////////////////////////////

//	loggingService.log("Warning: Default Message Authentication Code Mode Disabled! NOT compattible to MAC Mode Encrypted files!!!\r\n", true, true, true, false, false);
//	loggingService.log("Info:    Default Message Authentication Code Mode Enabled\r\n", true, true, true, false, false);

        DeviceManager deviceManager;
        if ((encrypt)) {
            if (finalCrypt.disableMAC) {
                loggingService.log("\"Warning: MAC Mode Disabled! (files will be encrypted without Message Authentication Code Header)\r\n", true, true, true, false, false);
            }

            if ((encryptablesFound)) {
                finalCrypt.encryptSelection(targetFCPathList, encryptableList, keyFCPath, true);
            } else {
                loggingService.log("No encryptable targets found:\r\n", false, true, true, true, false);
                loggingService.log(targetFCPathList.getStats(), false, true, false, false, false);
            }
        } else if ((decrypt)) {
            if (finalCrypt.disableMAC) {
                loggingService.log("Warning: MAC Mode Disabled! Use --encrypt if you know what you are doing!!!\r\n", true, true, true, false, false);
            } else {
                if (decryptablesFound) {
                    finalCrypt.encryptSelection(targetFCPathList, decryptableList, keyFCPath, false);
                } else {
                    loggingService.log("No decryptable targets found\r\n\r\n", false, true, true, true, false);
                    if (targetFCPathList.encryptedFiles > 0) {
                        loggingService.log("Wrong key? \"" + keyFCPath.path.toString() + "\"\r\n\r\n", false, true, false, false, false);
                    }
                    loggingService.log(targetFCPathList.getStats(), false, true, true, false, false);
                }
            }
        } else if (createkeydev) {
            if (createKeyDeviceFound) {
                deviceManager = new DeviceManager();
                deviceManager.start();
                deviceManager.createKeyDevice(keyFCPath, (FCPath) createKeyList.get(0));
            } else {
                loggingService.log("No valid target device found:\r\n", false, true, true, true, false);
                loggingService.log(targetFCPathList.getStats(), false, true, false, false, false);
            }
        } else if ((clonekeydev) && (cloneKeyDeviceFound)) {
            if (cloneKeyDeviceFound) {
                deviceManager = new DeviceManager();
                deviceManager.start();
                deviceManager.cloneKeyDevice(keyFCPath, (FCPath) cloneKeyList.get(0));
            } else {
                loggingService.log("No valid target device found:\r\n", false, true, true, true, false);
                loggingService.log(targetFCPathList.getStats(), false, true, false, false, false);
            }
        } else if ((printgpt) && (printGPTDeviceFound)) {
            if (printGPTDeviceFound) {
                deviceManager = new DeviceManager();
                deviceManager.start();
                deviceManager.printGPT((FCPath) printGPTTargetList.get(0));
            } else {
                loggingService.log("No valid target device found:\r\n", false, true, true, true, false);
                loggingService.log(targetFCPathList.getStats(), false, true, false, false, false);
            }
        } else if ((deletegpt) && (deleteGPTDeviceFound)) {
            if (deleteGPTDeviceFound) {
                deviceManager = new DeviceManager();
                deviceManager.start();
                deviceManager.deleteGPT((FCPath) deleteGPTTargetList.get(0));
            } else {
                loggingService.log("No valid target device found:\r\n", false, true, true, true, false);
                loggingService.log(targetFCPathList.getStats(), false, true, false, false, false);
            }
        }
    } // End of default constructor


//  =======================================================================================================================================================================

    public static FCPathList filter(ArrayList<FCPath> fcPathList, Predicate<FCPath> fcPath) {
        FCPathList result = new FCPathList();
        for (FCPath fcPathItem : fcPathList) {
            if (fcPath.test(fcPathItem)) {
                result.add(fcPathItem);
            }
        }
        return result;
    }

    public static Predicate<FCPath> isHidden() {
        return (FCPath fcPath) -> fcPath.isHidden;
    }

    public static void main(String[] args) {
        new CLUI(args);
    }

    private boolean addBatchTargetFiles(String batchFilePathString, ArrayList<Path> targetFilesPathList) {
        boolean ifset = false;
        Path batchFilePath;
        Path targetFilePath;
//		      isValidFile(UI ui, String caller,                       Path targetSourcePath, isKey	boolean device, long minSize, boolean symlink, boolean writable, boolean report)
        if (Validate.isValidFile("CLUI.addBatchTargetFiles", Paths.get(batchFilePathString), false, false, 1L, symlink, true, true)) {
            loggingService.log("Adding items from batchfile: " + batchFilePathString + "\r\n", false, true, true, false, false);
            batchFilePath = Paths.get(batchFilePathString);
            try {
                for (String targetFilePathString : Files.readAllLines(batchFilePath)) {
//                  Entry may not be a directory (gets filtered and must be a valid file)
//				  isValidFile(UI ui, String caller,                        Path targetSourcePath, boolean isKey, boolean device, long minSize, boolean symlink, boolean writable, boolean report)
                    if (Validate.isValidFile("CLUI.addBatchTargetFiles", Paths.get(targetFilePathString), false, false, 0L, symlink, true, true)) {
                        targetFilePath = Paths.get(targetFilePathString);
                        targetFilesPathList.add(targetFilePath);
                        ifset = true;
//                        println("Adding: " + targetFilePathString);
                    } else { /* println("Invalid file: " + targetFilePathString);*/ } // Reporting in isValidFile is already set to true, so if invalid then user is informed
                }
            } catch (IOException ex) {
                loggingService.log("Files.readAllLines(" + batchFilePath + ");" + ex.getMessage(), false, true, true, true, false);
            }
            if (!ifset) {
                loggingService.log("Warning: batchfile: " + batchFilePathString + " doesn't contain any valid items!\r\n", false, true, true, false, false);
            }
        } else {
            loggingService.log("Error: batchfile: " + batchFilePathString + " is not a valid file!\r\n", false, true, true, true, false);
        }
        return ifset;
    }

    public List<FCPath> filter(Predicate<FCPath> criteria, ArrayList<FCPath> list) {
        return list.stream().filter(criteria).collect(Collectors.<FCPath>toList());
    }

    private boolean validateIntegerString(String text) {
        try {
            Integer.parseInt(text);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private void usagePrompt(boolean error) {
        timeoutThread = new TimeoutThread(this);
        timeoutThread.start();
        readerThread = new ReaderThread(this);
        readerThread.start();
        while (timeoutThread.isAlive()) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ex) {
            }
        }
        loggingService.log("\r\n\r\n", false, true, false, false, false);
        System.exit(1);
    }

    protected void usage(boolean error) {

        String fileSeparator = java.nio.file.FileSystems.getDefault().getSeparator();
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("Examples:\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --examples   Print commandline examples.\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj.CLUI --create-keyfile -K mykeyfile -S 268435456 # (256 MiB) echo $((1024**2*256))\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --encrypt -k key_file -t target_file\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --encrypt -k key_file -t target_dir\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --encrypt -k key_file -t target_file -t target_dir\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("Usage:	    java -cp FinalCrypt.jar rdj/CLUI   <Mode>  [options] <Parameters>\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("Mode:\r\n", false, true, false, false, false);
        loggingService.log("            <--encrypt>           -k \"key_file\"   -t \"target\"	    Encrypt Targets.\r\n", false, true, false, false, false);
        loggingService.log("            <--decrypt>           -k \"key_file\"   -t \"target\"	    Decrypt Targets.\r\n", false, true, false, false, false);
        loggingService.log("            <--create-keydev>     -k \"key_file\"   -t \"target\"	    Create Key Device (only unix).\r\n", false, true, false, false, false);
        loggingService.log("            <--create-keyfile>    -K \"key_file\"   -S \"Size (bytes)\"	    Create OTP Key File.\r\n", false, true, false, false, false);
        loggingService.log("            <--clone-keydev>      -k \"source_device\" -t \"target_device\"     Clone Key Device (only unix).\r\n", false, true, false, false, false);
        loggingService.log("            [--print-gpt]         -t \"target_device\"			    Print GUID Partition Table.\r\n", false, true, false, false, false);
        loggingService.log("            [--delete-gpt]        -t \"target_device\"			    Delete GUID Partition Table (DATA LOSS!).\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("Options:\r\n", false, true, false, false, false);
        loggingService.log("            [-h] [--help]	  Shows this help page.\r\n", false, true, false, false, false);
        loggingService.log("            [--key-chksum]        -k \"key_file\"			    Calculate key checksum.\r\n", false, true, false, false, false);
        loggingService.log("            [-d] [--debug]        Enables debugging mode.\r\n", false, true, false, false, false);
        loggingService.log("            [-v] [--verbose]      Enables verbose mode.\r\n", false, true, false, false, false);
        loggingService.log("            [--print]		  Print all encrypted bytes.\r\n", false, true, false, false, false);
        loggingService.log("            [-l] [--symlink]      Include symlinks (can cause double encryption! Not recommended!).\r\n", false, true, false, false, false);
        loggingService.log("            [--disable-MAC]       Disable Message Authentication Code - (files will be encrypted without Message Authentication Code header).\r\n", false, true, false, false, false);
        loggingService.log("            [--version]           Print " + versionService.getProduct() + " version.\r\n", false, true, false, false, false);
        loggingService.log("            [--license]           Print " + versionService.getProduct() + " license.\r\n", false, true, false, false, false);
        loggingService.log("            [--check-update]      Check for online updates.\r\n", false, true, false, false, false);
        loggingService.log("                                  Warning: The above Print options slows encryption severely.\r\n", false, true, false, false, false);
        loggingService.log("            [-s size]             Changes default I/O buffer size (size = KiB) (default 1024 KiB).\r\n", false, true, false, false, false);
        loggingService.log("            [-S size]             OTP Key File Size (size = bytes). See --create-keyfile \r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("Filtering Options:\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            [--dry]               Dry run without encrypting files for safe testing purposes.\r\n", false, true, false, false, false);
        loggingService.log("            [-w \'wildcard\']       File wildcard INCLUDE filter. Uses: \"Globbing Patterns Syntax\".\r\n", false, true, false, false, false);
        loggingService.log("            [-W \'wildcard\']       File wildcard EXCLUDE filter. Uses: \"Globbing Patterns Syntax\".\r\n", false, true, false, false, false);
        loggingService.log("            [-r \'regex\']          File regular expression filter. Advanced filename filter!\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("Parameters:\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            <-k \"keyfile\">        The file that encrypts your file(s). Keep keyfile SECRET!\r\n", false, true, false, false, false);
        loggingService.log("                                  A key-file is a unique file like a personal photo or video!\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            <-t / -b>             The target items you want to encrypt. Individual (-t) or by batch (-b).\r\n", false, true, false, false, false);
        loggingService.log("            <[-t \"file/dir\"]>     Target file or dir you want to encrypt (encrypts dirs recursively).\r\n", false, true, false, false, false);
        loggingService.log("            <[-b \"batchfile\"]>    Batchfile with targetfiles you want to encrypt (only files accepted).\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log(VersionService.getProduct() + " " + versionService.checkCurrentlyInstalledVersion() + " - Author: " + VersionService.getAuthor() + " - Copyright: " + VersionService.getCopyright() + "\r\n\r\n", false, true, false, false, false);
        System.exit(error ? 1 : 0);
    }

    private void examples() {
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("Examples:   java -cp FinalCrypt.jar rdj/CLUI <Mode> [options] <Parameters>\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            # Encrypt / Decrypt myfile with mykeyfile\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --encrypt -k mykeyfile -t myfile\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --decrypt -k mykeyfile -t myfile\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            # Encrypt / Decrypt myfile and all content in mydir with mykeyfile\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --encrypt -k mykeyfile -t myfile -t mydir\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --decrypt -k mykeyfile -t myfile -t mydir\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            # Encrypt / Decrypt files in batchfile with mykeyfile\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --encrypt -k mykeyfile -b mybatchfile\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --decrypt -k mykeyfile -b mybatchfile\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            # Encrypt / Decrypt all files with *.bit extension in mydir with mykeyfile\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --encrypt -w '*.bit'-k mykeyfile -t mydir\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --decrypt -w '*.bit'-k mykeyfile -t mydir\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            # Encrypt / Decrypt all files without *.bit extension in mydir with mykeyfile\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --encrypt -W '*.bit' -k mykeyfile -t mydir \r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --decrypt -W '*.bit' -k mykeyfile -t mydir \r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            # Encrypt / Decrypt all files with *.bit extension in mydir with mykeyfile\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --encrypt -r '^.*\\.bit$' -k mykeyfile -t mydir\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --decrypt -r '^.*\\.bit$' -k mykeyfile -t mydir\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            # Encrypt / Decrypt all files excluding .bit extension in mydir with mykeyfile\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --encrypt -r '(?!.*\\.bit$)^.*$' -k mykeyfile -t mydir\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --decrypt -r '(?!.*\\.bit$)^.*$' -k mykeyfile -t mydir\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("Create OTP Key file:\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj.CLUI --create-keyfile -K mykeyfile -S 268435456 # (256 MiB) echo $((1024**2*256))\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("Key Device Examples (Linux):\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            # Create Key Device with 2 key partitions (e.g. on USB Mem Stick)\r\n", false, true, false, false, false);
        loggingService.log("            # Beware: keyfile gets randomized before writing to Device\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --create-keydev -k mykeyfile -t /dev/sdb\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            # Print GUID Partition Table\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --print-gpt -t /dev/sdb\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            # Delete GUID Partition Table\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --delete-gpt -t /dev/sdb\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            # Clone Key Device (-k sourcekeydevice -t destinationkeydevice)\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --clone-keydev -k /dev/sdb -t /dev/sdc\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log("            # Encrypt / Decrypt myfile with raw key partition\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --encrypt -k /dev/sdb1 -t myfile\r\n", false, true, false, false, false);
        loggingService.log("            java -cp FinalCrypt.jar rdj/CLUI --decrypt -k /dev/sdb1 -t myfile\r\n", false, true, false, false, false);
        loggingService.log("\r\n", false, true, false, false, false);
        loggingService.log(VersionService.getProduct() + " " + versionService.checkCurrentlyInstalledVersion() + " - Author: " + VersionService.getAuthor() + " - Copyright: " + VersionService.getCopyright() + "\r\n\r\n", false, true, false, false, false);
        System.exit(0);
    }

    public void buildReady(FCPathList fcPathListParam) {
        targetFCPathList = fcPathListParam;
    }

}

class ReaderThread extends Thread {
    private CLUI clui;

    public ReaderThread(CLUI ui) {
        this.clui = ui;
    }

    @Override
    public void run() {
        LoggingService.get().log("\r\nWould you like to see the User Manual (y/N)? ", false, true, false, false, false);
        try (Scanner in = new Scanner(System.in)) {
            String input = in.nextLine();
            if (input.trim().toLowerCase().equals("y")) {
                clui.usage(true);
            } else {
                LoggingService.get().log("\r\n", false, true, false, false, false);
                System.exit(1);
            }
        }
    }

}

class TimeoutThread extends Thread {
    private CLUI clui;

    public TimeoutThread(CLUI ui) {
        this.clui = ui;
    }

    @Override
    public void run() {
        try {
            Thread.sleep(2000);
//            Robot robot = new Robot();
//            robot.keyPress(KeyEvent.VK_ENTER);
//            robot.keyRelease(KeyEvent.VK_ENTER);
        } catch (Exception e) {
        }
    }

}
