package mambas.steganography.model;

import java.nio.file.Path;

public interface SteganographyService {

    /**
     * Hides secret message inside audio file.
     * @param coverFile Cover audio file.
     * @param secretFile Secret message file.
     * @param outputFile Output audio file.
     * @param options Steganography options (key, nLSB, etc).
     * @throws Exception if an error occurs.
     */
    void hideMessage(Path coverFile, Path secretFile, Path outputFile, StegoOptions options) throws Exception;

    /**
     * Extracts secret message from stego-audio file.
     * @param stegoFile Audio file containing the message.
     * @param outputFile File to save the extracted message.
     * @param options Steganography options (key, nLSB, etc).
     * @throws Exception if an error occurs.
     */
    void extractMessage(Path stegoFile, Path outputFile, StegoOptions options) throws Exception;

    /**
     * Calculates Peak Signal-to-Noise Ratio (PSNR).
     * @param originalFile Original audio file.
     * @param stegoFile Steganographed audio file.
     * @return PSNR value in dB.
     * @throws Exception if an error occurs.
     */
    double calculatePSNR(Path originalFile, Path stegoFile) throws Exception;
}
