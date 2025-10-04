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
 * Implements a simplified steganography service. This version does NOT parse
 * frame headers. It finds the first frame and embeds data until it encounters
 * what it assumes is the next frame's sync word.
 * WARNING: This approach is not robust and can fail if a sync word pattern
 * appears by chance within the audio data ("false positive").
 */
public class SteganographyServiceImpl implements SteganographyService {

    private static final byte[] MAGIC_BYTES = "STGO".getBytes(StandardCharsets.UTF_8);
    private static final int METADATA_SIZE = 286;
    private static final int FILENAME_MAX_LEN = 255;
    private static final int FILE_EXT_MAX_LEN = 15;

    // --- HELPER METHODS FOR THE SIMPLIFIED ALGORITHM ---

    /**
     * Checks if the bytes at a given offset represent an MP3 sync word.
     * A sync word is 11 consecutive '1' bits.
     */
    private boolean isSyncWord(byte[] data, int offset) {
        if (offset + 1 >= data.length) {
            return false;
        }
        return (data[offset] & 0xFF) == 0xFF && (data[offset + 1] & 0xE0) == 0xE0;
    }

    /**
     * Finds the next occurrence of a sync word in the data.
     * @param data The byte array to search.
     * @param startOffset The position to start searching from.
     * @return The offset of the next sync word, or -1 if not found.
     */
    private int findNextSyncWord(byte[] data, int startOffset) {
        for (int i = startOffset; i < data.length - 1; i++) {
            if (isSyncWord(data, i)) {
                return i;
            }
        }
        return -1;
    }

    // --- CORE IMPLEMENTATION (REWRITTEN) ---

    @Override
    public void hideMessage(Path coverFile, Path secretFile, Path outputFile, StegoOptions options) throws Exception {
        byte[] coverBytes = Files.readAllBytes(coverFile);
        int dataOffset = findAudioDataOffset(coverFile);
        byte[] audioData = Arrays.copyOfRange(coverBytes, dataOffset, coverBytes.length);

        byte[] secretBytes = Files.readAllBytes(secretFile);
        if (options.encrypt()) {
            secretBytes = encryptDecrypt(secretBytes, options.key(), true);
        }

        byte[] metadata = createMetadata(secretFile, secretBytes.length, options);

        // Capacity check is now an approximation
        if ((long) (metadata.length + secretBytes.length) * 8 > (long) audioData.length * options.nLsb()) {
            throw new IllegalArgumentException("Secret file is too large for the available space.");
        }

        byte[] stegoAudioData = embedPayloadBySearching(audioData, metadata, 0, options.nLsb());

        // This is a simplified calculation for the start offset
        int approxMetadataBytesUsed = (int)Math.ceil((double)metadata.length * 8 / options.nLsb());
        int secretStartOffset = getSecretStartOffset(options.key(), audioData.length, approxMetadataBytesUsed, secretBytes.length, options.nLsb(), options.randomStart());

        stegoAudioData = embedPayloadBySearching(stegoAudioData, secretBytes, secretStartOffset, options.nLsb());

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(coverBytes, 0, dataOffset);
        outputStream.write(stegoAudioData);
        Files.write(outputFile, outputStream.toByteArray());
    }

    @Override
    public void extractMessage(Path stegoFile, Path outputFile, StegoOptions options) throws Exception {
        byte[] stegoBytes = Files.readAllBytes(stegoFile);
        int dataOffset = findAudioDataOffset(stegoFile);
        byte[] stegoAudioData = Arrays.copyOfRange(stegoBytes, dataOffset, stegoBytes.length);

        byte[] extractedMetadata = extractPayloadBySearching(stegoAudioData, 0, METADATA_SIZE, options.nLsb());

        ByteBuffer metaBuffer = ByteBuffer.wrap(extractedMetadata);
        byte[] magic = new byte[4];
        metaBuffer.get(magic);
        if (!Arrays.equals(magic, MAGIC_BYTES)) {
            throw new IllegalArgumentException("Invalid stego file or incorrect nLsb: magic bytes 'STGO' not found.");
        }

        long secretFileLength = metaBuffer.getLong();
        metaBuffer.position(4 + 8 + 1 + FILENAME_MAX_LEN + 1 + FILE_EXT_MAX_LEN);
        boolean isEncrypted = (options.encrypt());
        boolean isRandomStart = (options.randomStart());
        int nLsb = options.nLsb();

        int approxMetadataBytesUsed = (int)Math.ceil((double)METADATA_SIZE * 8 / nLsb);
        int secretStartOffset = getSecretStartOffset(options.key(), stegoAudioData.length, approxMetadataBytesUsed, (int)secretFileLength, nLsb, isRandomStart);

        byte[] extractedSecretBytes = extractPayloadBySearching(stegoAudioData, secretStartOffset, (int) secretFileLength, nLsb);

        if (isEncrypted) {
            extractedSecretBytes = encryptDecrypt(extractedSecretBytes, options.key(), false);
        }

        Files.write(outputFile, extractedSecretBytes);
    }

    private byte[] embedPayloadBySearching(byte[] audioData, byte[] payload, int startOffset, int nLsb) {
        byte[] result = audioData.clone();
        int mask = (0xFF << nLsb) & 0xFF;
        int bitPool = 0;
        int bitPoolSize = 0;
        int payloadIndex = 0;

        int audioCursor = startOffset;
        while (audioCursor < result.length && payloadIndex < payload.length) {
            // Find the start of the current frame's data. It's 4 bytes after the sync word.
            int dataStart = findNextSyncWord(result, audioCursor);
            if (dataStart == -1) break; // No more frames
            dataStart += 4; // Skip the header

            // Find where the next frame starts. This marks the end of our current data block.
            int nextFrameStart = findNextSyncWord(result, dataStart);
            if (nextFrameStart == -1) {
                nextFrameStart = result.length; // Embed until the end of the file
            }

            // Embed within the identified data block
            for (int i = dataStart; i < nextFrameStart && payloadIndex < payload.length; i++) {
                while (bitPoolSize < nLsb && payloadIndex < payload.length) {
                    bitPool = (bitPool << 8) | (payload[payloadIndex++] & 0xFF);
                    bitPoolSize += 8;
                }
                if (bitPoolSize >= nLsb) {
                    int bitsToEmbed = (bitPool >> (bitPoolSize - nLsb)) & ((1 << nLsb) - 1);
                    result[i] = (byte) ((result[i] & mask) | bitsToEmbed);
                    bitPoolSize -= nLsb;
                }
            }
            audioCursor = nextFrameStart;
        }
        return result;
    }

    private byte[] extractPayloadBySearching(byte[] audioData, int startOffset, int payloadLength, int nLsb) {
        ByteArrayOutputStream extractedStream = new ByteArrayOutputStream();
        int mask = (1 << nLsb) - 1;
        int bitPool = 0;
        int bitPoolSize = 0;

        int audioCursor = startOffset;
        while (audioCursor < audioData.length && extractedStream.size() < payloadLength) {
            int dataStart = findNextSyncWord(audioData, audioCursor);
            if (dataStart == -1) break;
            dataStart += 4;

            int nextFrameStart = findNextSyncWord(audioData, dataStart);
            if (nextFrameStart == -1) {
                nextFrameStart = audioData.length;
            }

            for (int i = dataStart; i < nextFrameStart && extractedStream.size() < payloadLength; i++) {
                int lsbBits = audioData[i] & mask;
                bitPool = (bitPool << nLsb) | lsbBits;
                bitPoolSize += nLsb;
                if (bitPoolSize >= 8) {
                    int extractedByte = (bitPool >> (bitPoolSize - 8)) & 0xFF;
                    extractedStream.write(extractedByte);
                    bitPoolSize -= 8;
                }
            }
            audioCursor = nextFrameStart;
        }
        return extractedStream.toByteArray();
    }

    // This is now an approximation.
    private int getSecretStartOffset(String key, int audioDataLength, int metadataBytesUsed, int secretLength, int nLsb, boolean randomStart) {
        if (!randomStart) {
            return metadataBytesUsed;
        }
        long secretBytesNeededInAudio = (long)Math.ceil((double)secretLength * 8 / nLsb);
        int availableRandomRange = (int)(audioDataLength - metadataBytesUsed - secretBytesNeededInAudio);

        if (availableRandomRange <= 0) {
            return metadataBytesUsed;
        }

        long seed = 0;
        for (char c : key.toCharArray()) seed += c;
        Random random = new Random(seed);

        return metadataBytesUsed + random.nextInt(availableRandomRange);
    }

    // --- UNCHANGED OR MINORLY CHANGED METHODS BELOW ---

    @Override
    public double calculatePSNR(Path originalFile, Path stegoFile) throws Exception {
        byte[] originalBytes = Files.readAllBytes(originalFile);
        byte[] stegoBytes = Files.readAllBytes(stegoFile);

        int originalOffset = findAudioDataOffset(originalFile);
        int stegoOffset = findAudioDataOffset(stegoFile);

        byte[] originalAudio = Arrays.copyOfRange(originalBytes, originalOffset, originalBytes.length);
        byte[] stegoAudio = Arrays.copyOfRange(stegoBytes, stegoOffset, stegoBytes.length);

        double sumOfSquares = 0.0;
        int minLength = Math.min(originalAudio.length, stegoAudio.length);
        for (int i = 0; i < minLength; i++) {
            double diff = (originalAudio[i] & 0xFF) - (stegoAudio[i] & 0xFF);
            sumOfSquares += diff * diff;
        }

        if (sumOfSquares == 0.0) return Double.POSITIVE_INFINITY;

        double mse = sumOfSquares / minLength;
        return 10 * Math.log10((255.0 * 255.0) / mse);
    }

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
        buffer.position(4 + 8 + 1 + FILENAME_MAX_LEN);
        buffer.put((byte) fileExtBytes.length);
        buffer.put(fileExtBytes);
        buffer.position(4 + 8 + 1 + FILENAME_MAX_LEN + 1 + FILE_EXT_MAX_LEN);
        buffer.put((byte) (options.encrypt() ? 1 : 0));
        buffer.put((byte) (options.randomStart() ? 1 : 0));

        return buffer.array();
    }

    // Vigenere Cipher
    private byte[] encryptDecrypt(byte[] data, String key, boolean encrypt) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty for encryption/decryption.");
        }
        byte[] result = new byte[data.length];
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < data.length; i++) {
            int dataByte = data[i] & 0xFF;
            int shift = keyBytes[i % keyBytes.length] & 0xFF;

            int processedByte;
            if (encrypt) {
                processedByte = (dataByte + shift) % 256;      // Enkripsi
            } else {
                processedByte = (dataByte - shift + 256) % 256; // Dekripsi
            }

            result[i] = (byte) processedByte;
        }
        return result;
    }

    private int findAudioDataOffset(Path filePath) throws Exception {
        MP3File mp3File = new MP3File(filePath.toFile());
        MP3AudioHeader audioHeader = mp3File.getMP3AudioHeader();
        return (int) audioHeader.getMp3StartByte();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
            result.append(" ");
        }
        return result.toString();
    }
}
