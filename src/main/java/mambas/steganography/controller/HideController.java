package mambas.steganography.controller;

import mambas.steganography.model.SteganographyService;
import mambas.steganography.model.StegoOptions;
import mambas.steganography.view.SteganographyView;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name = "hide", description = "Hide secret file into audio file.")
public class HideController implements Callable<Integer> {

    private final SteganographyService service;
    private final SteganographyView view;

    public HideController(SteganographyService service, SteganographyView view) {
        this.service = service;
        this.view = view;
    }

    @Option(names = {"-c", "--cover"}, required = true, description = "Audio file (MP3) as cover medium.")
    private Path coverFile;

    @Option(names = {"-s", "--secret"}, required = true, description = "Secret file to be hidden.")
    private Path secretFile;

    @Option(names = {"-o", "--output"}, required = true, description = "Output stego-audio file name.")
    private Path outputFile;

    @Option(names = {"-n", "--nlsb"}, required = true, description = "Number of LSB used (1-4).")
    private int nLsb;

    @Option(names = {"-e", "--encrypt"}, description = "Use Vigenere encryption on secret file.")
    private boolean encrypt;

    @Option(names = {"-r", "--random-start"}, description = "Use random starting point for insertion.")
    private boolean randomStart;

    @Option(names = {"-k", "--key"}, description = "Key for encryption and/or seed.")
    private String key;

    @Override
    public Integer call() {
        try {
            validateInputs();
            StegoOptions options = new StegoOptions(key, nLsb, encrypt, randomStart);
            view.showMessage("Starting hiding process...");
            service.hideMessage(coverFile, secretFile, outputFile, options);
            view.showSuccess("Message successfully hidden into: " + outputFile.toAbsolutePath());
            return 0;
        } catch (Exception e) {
            view.showError(e.getMessage());
            // e.printStackTrace(); // Uncomment for debugging
            return 1;
        }
    }

    private void validateInputs() {
        if (!Files.exists(coverFile)) throw new IllegalArgumentException("Cover file not found: " + coverFile);
        if (!Files.exists(secretFile)) throw new IllegalArgumentException("Secret file not found: " + secretFile);
        if (nLsb < 1 || nLsb > 4) throw new IllegalArgumentException("n-LSB must be between 1 and 4.");
    }
}
