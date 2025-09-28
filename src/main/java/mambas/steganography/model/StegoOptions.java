package mambas.steganography.model;

public record StegoOptions(String key, int nLsb, boolean encrypt, boolean randomStart) {
}
