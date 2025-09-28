package mambas.steganography.controller;

import mambas.steganography.model.SteganographyService;
import mambas.steganography.model.StegoOptions;
import mambas.steganography.view.SteganographyView;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name = "extract", description = "Extract secret file from audio file.")
public class ExtractController implements Callable<Integer> {

    private final SteganographyService service;
    private final SteganographyView view;

    public ExtractController(SteganographyService service, SteganographyView view) {
        this.service = service;
        this.view = view;
    }

    @Option(names = {"-i", "--input"}, required = true, description = "Stego-audio file (MP3) containing the message.")
    private Path inputFile;

    @Option(names = {"-o", "--output"}, required = true, description = "Output file name for the secret message.")
    private Path outputFile;

    @Option(names = {"-n", "--nlsb"}, required = true, description = "Number of LSB used (1-4).")
    private int nLsb;

    @Option(names = {"-e", "--encrypt"}, description = "Flag indicating the message is encrypted (requires key).")
    private boolean encrypt;

    @Option(names = {"-r", "--random-start"}, description = "Flag indicating random starting point for insertion is used.")
    private boolean randomStart;

    @Option(names = {"-k", "--key"}, description = "Key for decryption and/or seed.")
    private String key;

    @Override
    public Integer call() {
        try {
            validateInputs();
            StegoOptions options = new StegoOptions(key, nLsb, encrypt, randomStart);
            view.showMessage("Starting extraction process...");
            service.extractMessage(inputFile, outputFile, options);
            view.showSuccess("Message successfully extracted. Check file in " + outputFile.getParent());
            return 0;
        } catch (Exception e) {
            view.showError(e.getMessage());
            e.printStackTrace(); // Uncomment for debugging
            return 1;
        }
    }

    private void validateInputs() {
        if (!Files.exists(inputFile)) throw new IllegalArgumentException("Input file not found: " + inputFile);
        if (nLsb < 1 || nLsb > 4) throw new IllegalArgumentException("n-LSB must be between 1 and 4.");
    }
}
