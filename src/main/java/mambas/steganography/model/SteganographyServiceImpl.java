package mambas.steganography.model;

import org.jaudiotagger.audio.mp3.MP3AudioHeader;
import org.jaudiotagger.audio.mp3.MP3File;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Random;

/**
 * Implements the SteganographyService interface to hide and extract files
 * within MP3 audio files using the LSB (Least Significant Bit) method.
 * Uses JAudioTagger for reliable MP3 metadata parsing.
 */
public class SteganographyServiceImpl implements SteganographyService {

    private static final byte[] MAGIC_BYTES = "STGO".getBytes(StandardCharsets.UTF_8);
    private static final int METADATA_SIZE = 287; // Total size of the metadata block
    private static final int FILENAME_MAX_LEN = 255;
    private static final int FILE_EXT_MAX_LEN = 15;

    @Override
    public void hideMessage(Path coverFile, Path secretFile, Path outputFile, StegoOptions options) throws Exception {
        // 1. Read cover audio and secret file bytes
        byte[] coverBytes = Files.readAllBytes(coverFile);
        byte[] secretBytes = Files.readAllBytes(secretFile);

        // 2. Reliably separate MP3 headers from the audio data payload using JAudioTagger
        int dataOffset = findAudioDataOffset(coverFile);
        byte[] audioData = Arrays.copyOfRange(coverBytes, dataOffset, coverBytes.length);

        // 3. Encrypt secret file if requested
        if (options.encrypt()) {
            secretBytes = encryptDecrypt(secretBytes, options.key());
        }

        // 4. Create metadata block
        byte[] metadata = createMetadata(secretFile, secretBytes.length, options);

        // 5. Combine metadata and secret data into a single payload
        ByteArrayOutputStream payloadStream = new ByteArrayOutputStream();
        payloadStream.write(metadata);
        payloadStream.write(secretBytes);
        byte[] payloadToHide = payloadStream.toByteArray();

        // 6. Check capacity
        long capacity = (long) audioData.length * options.nLsb() / 8;
        if (payloadToHide.length > capacity) {
            throw new IllegalArgumentException(
                    "Secret file is too large. Required: " + payloadToHide.length + " bytes, Available: " + capacity + " bytes."
            );
        }

        // 7. Determine starting position for hiding
        int startIndex = getStartIndex(options.key(), audioData.length, payloadToHide.length, options.nLsb(), options.randomStart());

        // 8. Perform LSB hiding
        byte[] stegoAudioData = embedPayload(audioData, payloadToHide, startIndex, options.nLsb());

        // 9. Write the final stego MP3 file (original headers + modified audio data)
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(coverBytes, 0, dataOffset);
        outputStream.write(stegoAudioData);
        Files.write(outputFile, outputStream.toByteArray());
    }

    @Override
    public void extractMessage(Path stegoFile, Path outputFile, StegoOptions options) throws Exception {
        // 1. Read stego file and separate headers from audio data
        byte[] stegoBytes = Files.readAllBytes(stegoFile);
        int dataOffset = findAudioDataOffset(stegoFile);
        byte[] stegoAudioData = Arrays.copyOfRange(stegoBytes, dataOffset, stegoBytes.length);

        // 2. Determine the start index using the *provided* options to read metadata
        int tempNLsb = options.nLsb();
        int placeholderPayloadLength = METADATA_SIZE;
        int startIndex = getStartIndex(options.key(), stegoAudioData.length, placeholderPayloadLength, tempNLsb, options.randomStart());

        byte[] extractedMetadata = extractPayload(stegoAudioData, startIndex, METADATA_SIZE, tempNLsb);

        // 3. Parse metadata
        ByteBuffer metaBuffer = ByteBuffer.wrap(extractedMetadata);
        byte[] magic = new byte[4];
        metaBuffer.get(magic);
        if (!Arrays.equals(magic, MAGIC_BYTES)) {
            throw new IllegalArgumentException("Invalid stego file: magic bytes 'STGO' not found.");
        }

        long secretFileLength = metaBuffer.getLong();
        // Skip filename, we don't need it for extraction logic
        metaBuffer.position(4 + 8 + 1 + FILENAME_MAX_LEN + 1 + FILE_EXT_MAX_LEN);

        boolean isEncrypted = (metaBuffer.get() == 1);
        boolean isRandomStart = (metaBuffer.get() == 1);
        int nLsb = metaBuffer.get() & 0xFF;

        // 4. If the start was random, we must recalculate the start index
        // using the now-known actual payload size and nLsb from the metadata.
        if (isRandomStart) {
            long totalPayloadLength = METADATA_SIZE + secretFileLength;
            startIndex = getStartIndex(options.key(), stegoAudioData.length, (int)totalPayloadLength, nLsb, true);
        }

        // 5. Extract the secret file content
        int dataStartIndex = startIndex + (METADATA_SIZE * 8 / nLsb);
        byte[] extractedSecretBytes = extractPayload(stegoAudioData, dataStartIndex, (int) secretFileLength, nLsb);

        // 6. Decrypt if necessary
        if (isEncrypted) {
            extractedSecretBytes = encryptDecrypt(extractedSecretBytes, options.key());
        }

        // 7. Write to output file
        Files.write(outputFile, extractedSecretBytes);
    }

    @Override
    public double calculatePSNR(Path originalFile, Path stegoFile) throws Exception {
        byte[] originalBytes = Files.readAllBytes(originalFile);
        byte[] stegoBytes = Files.readAllBytes(stegoFile);

        int originalOffset = findAudioDataOffset(originalFile);
        int stegoOffset = findAudioDataOffset(stegoFile);

        byte[] originalAudio = Arrays.copyOfRange(originalBytes, originalOffset, originalBytes.length);
        byte[] stegoAudio = Arrays.copyOfRange(stegoBytes, stegoOffset, stegoBytes.length);

        if (originalAudio.length != stegoAudio.length) {
            // Trim the longer array to match the shorter one for a valid comparison
            int minLength = Math.min(originalAudio.length, stegoAudio.length);
            originalAudio = Arrays.copyOf(originalAudio, minLength);
            stegoAudio = Arrays.copyOf(stegoAudio, minLength);
        }

        double sumOfSquares = 0.0;
        for (int i = 0; i < originalAudio.length; i++) {
            double diff = (originalAudio[i] & 0xFF) - (stegoAudio[i] & 0xFF);
            sumOfSquares += diff * diff;
        }

        if (sumOfSquares == 0.0) {
            return Double.POSITIVE_INFINITY; // Identical files.
        }

        double mse = sumOfSquares / originalAudio.length;
        double maxSignalValue = 255.0; // For 8-bit samples.
        return 10 * Math.log10((maxSignalValue * maxSignalValue) / mse);
    }

    // --- Private Helper Methods ---

    /**
     * Creates the 287-byte metadata header.
     */
    private byte[] createMetadata(Path secretFile, long secretFileLength, StegoOptions options) {
        String fullFileName = secretFile.getFileName().toString();
        String baseName = fullFileName;
        String extension = "";
        int dotIndex = fullFileName.lastIndexOf('.');
        if (dotIndex > 0 && dotIndex < fullFileName.length() - 1) {
            baseName = fullFileName.substring(0, dotIndex);
            extension = fullFileName.substring(dotIndex + 1);
        }

        byte[] fileNameBytes = baseName.getBytes(StandardCharsets.UTF_8);
        byte[] fileExtBytes = extension.getBytes(StandardCharsets.UTF_8);

        ByteBuffer buffer = ByteBuffer.allocate(METADATA_SIZE);
        buffer.put(MAGIC_BYTES);
        buffer.putLong(secretFileLength);
        buffer.put((byte) fileNameBytes.length);
        buffer.put(fileNameBytes);
        buffer.position(4 + 8 + 1 + FILENAME_MAX_LEN); // Move position past filename block
        buffer.put((byte) fileExtBytes.length);
        buffer.put(fileExtBytes);
        buffer.position(4 + 8 + 1 + FILENAME_MAX_LEN + 1 + FILE_EXT_MAX_LEN); // Move position past extension block
        buffer.put((byte) (options.encrypt() ? 1 : 0));
        buffer.put((byte) (options.randomStart() ? 1 : 0));
        buffer.put((byte) options.nLsb());
        return buffer.array();
    }

    /**
     * Embeds the payload into the audio data using LSB.
     */
    private byte[] embedPayload(byte[] audioData, byte[] payload, int startByte, int nLsb) {
        byte[] result = audioData.clone();
        int mask = (0xFF << nLsb) & 0xFF;
        int bitPool = 0;
        int bitPoolSize = 0;
        int payloadIndex = 0;
        int audioIndex = startByte;

        while (payloadIndex < payload.length && audioIndex < result.length) {
            while (bitPoolSize < nLsb && payloadIndex < payload.length) {
                int nextPayloadByte = payload[payloadIndex++] & 0xFF;
                bitPool = (bitPool << 8) | nextPayloadByte;
                bitPoolSize += 8;
            }

            if (bitPoolSize >= nLsb) {
                int bitsToEmbed = (bitPool >> (bitPoolSize - nLsb)) & ((1 << nLsb) - 1);
                result[audioIndex] = (byte) ((result[audioIndex] & mask) | bitsToEmbed);
                bitPoolSize -= nLsb;
                audioIndex++;
            }
        }
        return result;
    }

    /**
     * Extracts a payload of a given length from the audio data.
     */
    private byte[] extractPayload(byte[] audioData, int startByte, int payloadLength, int nLsb) {
        ByteArrayOutputStream extractedStream = new ByteArrayOutputStream();
        int mask = (1 << nLsb) - 1;
        int bitPool = 0;
        int bitPoolSize = 0;
        int audioIndex = startByte;

        while (extractedStream.size() < payloadLength && audioIndex < audioData.length) {
            int lsbBits = audioData[audioIndex++] & mask;
            bitPool = (bitPool << nLsb) | lsbBits;
            bitPoolSize += nLsb;

            if (bitPoolSize >= 8) {
                int extractedByte = (bitPool >> (bitPoolSize - 8)) & 0xFF;
                extractedStream.write(extractedByte);
                bitPoolSize -= 8;
            }
        }
        return extractedStream.toByteArray();
    }

    /**
     * Implements a simple XOR-based cipher.
     */
    private byte[] encryptDecrypt(byte[] data, String key) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty for encryption/decryption.");
        }
        byte[] result = new byte[data.length];
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ keyBytes[i % keyBytes.length]);
        }
        return result;
    }

    /**
     * Determines the starting byte for hiding, potentially randomly.
     */
    private int getStartIndex(String key, int audioDataLength, int payloadLength, int nLsb, boolean randomStart) {
        if (!randomStart) {
            return 0;
        }
        long requiredBytesInAudio = (long) Math.ceil((double) payloadLength * 8 / nLsb);
        if (requiredBytesInAudio >= audioDataLength) {
            return 0;
        }

        int maxStartIndex = (int) (audioDataLength - requiredBytesInAudio);

        long seed = 0;
        for (char c : key.toCharArray()) {
            seed += c;
        }
        Random random = new Random(seed);
        return random.nextInt(maxStartIndex);
    }

    /**
     * Finds the offset of the first MP3 frame using JAudioTagger.
     * This is the reliable way to skip ID3 tags.
     */
    private int findAudioDataOffset(Path filePath) throws Exception {
        MP3File mp3File = new MP3File(filePath.toFile());
        MP3AudioHeader audioHeader = mp3File.getMP3AudioHeader();
        return (int) audioHeader.getMp3StartByte();
    }
}
