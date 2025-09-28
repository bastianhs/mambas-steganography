# Steganography in Audio Files Using Multiple-LSB Method

## Features
   - Embed & Extract: Hides secret message files (.jpeg, .pdf, .doc, .exe, etc.) within MP3 audio files and extracts them.
   - Steganography Method: Implements the Multiple Least Significant Bit (multiple-LSB) technique.
   - Randomized Embedding: Allows the data to be hidden starting from a random point, which is determined by a user-defined seed.
   - Encryption Support: Encrypts the secret message using the extended Vigenere cipher (full 256-character set) for an added layer of security.

## Tech Stack
   - Java (Java JDK 25)
   - Apache Maven 3.9.11

## Dependencies
   - [mp3spi](https://central.sonatype.com/artifact/com.googlecode.soundlibs/mp3spi): For handling MP3 audio files.
   - [picocli](https://central.sonatype.com/artifact/info.picocli/picocli): For building command-line interfaces.

## How to Run the Program
   1. Install Java JDK
   2. Go to the project root directory
   3. (optional) Install Apache Maven, then build the project using Maven
      ```bash
      mvn clean package
      ```
      After building, the JAR file will be created in the `target` directory.  
      The JAR file name will be `steganography-1.0-SNAPSHOT.jar`.
   4. Run the program using the following command:
      ```bash
      java -jar target/steganography-1.0-SNAPSHOT.jar [options]
      ```

## Command-Line Options
   Example for displaying help:
   ```bash
   java -jar target/steganography-1.0-SNAPSHOT.jar --help
   java -jar target/steganography-1.0-SNAPSHOT.jar hide --help
   ```

   Example for hiding message:
   ```bash
   java -jar target/steganography-1.0-SNAPSHOT.jar hide \
   --cover="path/to/your/music.mp3" \
   --secret="path/to/your/secret.pdf" \
   --output="path/to/stego_music.mp3" \
   --nlsb=2 \
   --encrypt \
   --random-start \
   --key="secretkey123"
   ```

   Example for extracting message:  
   (sementara output file wajib dituliskan)
   ```bash
   java -jar target/steganography-1.0-SNAPSHOT.jar extract \
   --input="path/to/stego_music.mp3" \
   --output="path/to/extracted_secret.pdf" \
   --nlsb=2 \
   --encrypt \
   --random-start \
   --key="secretkey123"
   ```

   Example for comparing original and extracted files with PSNR (Peak Signal-to-Noise Ratio):
   ```bash
   java -jar target/steganography-1.0-SNAPSHOT.jar psnr \
   --original="path/to/your/music.mp3" \
   --steganographed="path/to/stego_music.mp3"    
   ```
