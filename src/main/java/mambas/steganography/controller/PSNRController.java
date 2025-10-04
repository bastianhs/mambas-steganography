package mambas.steganography.controller;

import mambas.steganography.model.SteganographyService;
import mambas.steganography.view.SteganographyView;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name = "psnr", description = "Calculate PSNR value between two audio files.")
public class PSNRController implements Callable<Integer> {

    private final SteganographyService service;
    private final SteganographyView view;

    public PSNRController(SteganographyService service, SteganographyView view) {
        this.service = service;
        this.view = view;
    }

    @Option(names = {"-orig", "--original"}, required = true, description = "Original audio file.")
    private Path originalFile;

    @Option(names = {"-stego", "--steganographed"}, required = true, description = "Steganographed audio file.")
    private Path stegoFile;

    @Override
    public Integer call() {
        try {
            validateInputs();
            view.showMessage("Calculating PSNR...");
            double psnr = service.calculatePSNR(originalFile, stegoFile);
            view.showSuccess(String.format("PSNR value is: %.2f dB", psnr));
            return 0;
        } catch (Exception e) {
            view.showError(e.getMessage());
            // e.printStackTrace(); // Uncomment for debugging
            return 1;
        }
    }

    private void validateInputs() {
        if (!Files.exists(originalFile)) throw new IllegalArgumentException("Original file not found.");
        if (!Files.exists(stegoFile)) throw new IllegalArgumentException("Stego file not found.");
    }
}
