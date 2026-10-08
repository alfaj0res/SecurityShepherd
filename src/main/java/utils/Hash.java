package utils;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Class used for miscellaneous Hash use <br>
 * <br>
 * This file is part of the Security Shepherd Project.
 *
 * <p>The Security Shepherd project is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.<br>
 *
 * <p>The Security Shepherd project is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.<br>
 *
 * <p>You should have received a copy of the GNU General Public License along with the Security
 * Shepherd project. If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Mark Denihan
 */
public class Hash {

  private static final Logger log = LogManager.getLogger(Hash.class);
  private static byte[] serverEncryptionKey = randomKeyBytes();
  // Separate random AES key used only to encrypt values shown to clients. It never leaves the
  // server
  private static final SecretKeySpec displayEncryptionKey =
      new SecretKeySpec(randomKeyBytes(), "AES");

  /**
   * Generates HMAC with servers random encryption key on user name concatenated with level's base
   * result key in a user friendly HTML form
   *
   * @param baseKey The stored result key for the module
   * @param userSalt Something specific to the user (User name)
   * @return User Specific Solution in a user friendly HTML form
   */
  public static String generateUserSolution(String baseKey, String userSalt) {
    log.debug("Generating User Solution...");
    String toReturn = "Key Should be here! Please refresh the home page and try again!";
    String userSpecificSolution = generateUserSolutionKeyOnly(baseKey, userSalt);
    if (userSpecificSolution != null) {
      toReturn =
          "<script>prepTooltips();prepClipboardEvents();</script><div class='input-group'><textarea"
              + " id='theKey' rows=2 style='height: 30px; display: inline-block; float: left;"
              + " padding-right: 1em; overflow: hidden; width:85%'>"
              + userSpecificSolution
              + "</textarea><span class='input-group-button'><button class='btn' type='button'"
              + " data-clipboard-shepherd data-clipboard-target='#theKey' style='height:"
              + " 30px;'><img src='../js/clipboard-js/clippy.svg' width='14' alt='Copy to"
              + " clipboard'></button></span><p>&nbsp;</p></div>";
    }
    return toReturn;
  }

  /**
   * Generates HMAC with servers random encryption key on user name concatenated with level's base
   * result key
   *
   * @param baseKey The stored result key for the module
   * @param userSalt Something specific to the user (User name)
   * @return User Specific Solution Key
   */
  public static String generateUserSolutionKeyOnly(String baseKey, String userSalt) {
    log.debug("Generating User Solution...");
    String toReturn = null;
    try {
      Mac sha512_HMAC = null;
      final String HMAC_SHA512 = "HmacSHA512";
      sha512_HMAC = Mac.getInstance(HMAC_SHA512);
      byte[] key = getCurrentKey();
      SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_SHA512);
      sha512_HMAC.init(keySpec);
      byte[] mac_data = sha512_HMAC.doFinal((baseKey + userSalt).getBytes("UTF-16"));
      StringBuilder sb = new StringBuilder();
      for (byte b : mac_data) {
        sb.append(String.format("%02X", b));
      }
      String userSpecificSolution = sb.toString();
      log.debug("Returning: " + userSpecificSolution);
      toReturn = userSpecificSolution;
    } catch (Exception e) {
      log.error("Encrypt Failure: " + e.toString());
    }
    return toReturn;
  }

  /**
   * Encrypts a value with AES-GCM under a random key that only exists in server memory. The output
   * (Base64 of IV and ciphertext) can be shown to clients without revealing the value.
   *
   * @param plainText Value to encrypt
   * @return Base64 encoded IV and ciphertext
   */
  public static String encryptWithServerKey(String plainText) {
    try {
      byte[] iv = new byte[12];
      new SecureRandom().nextBytes(iv);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, displayEncryptionKey, new GCMParameterSpec(128, iv));
      byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF-8"));
      byte[] output = new byte[iv.length + cipherText.length];
      System.arraycopy(iv, 0, output, 0, iv.length);
      System.arraycopy(cipherText, 0, output, iv.length, cipherText.length);
      return java.util.Base64.getEncoder().encodeToString(output);
    } catch (Exception e) {
      log.error("Could not encrypt value: " + e.toString());
      throw new RuntimeException(e);
    }
  }

  /**
   * Decrypts a value produced by {@link #encryptWithServerKey(String)}. Tampered or foreign values
   * fail the GCM integrity check and are rejected.
   *
   * @param encrypted Base64 encoded IV and ciphertext
   * @return The decrypted value
   * @throws GeneralSecurityException If the value was not produced with the server key
   */
  public static String decryptWithServerKey(String encrypted) throws GeneralSecurityException {
    byte[] input = java.util.Base64.getDecoder().decode(encrypted.trim());
    if (input.length < 12 + 16) {
      throw new GeneralSecurityException("Encrypted value too short");
    }
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, displayEncryptionKey, new GCMParameterSpec(128, input, 0, 12));
    byte[] plainText = cipher.doFinal(input, 12, input.length - 12);
    return new String(plainText, java.nio.charset.StandardCharsets.UTF_8);
  }

  public static byte[] getCurrentKey() {
    return serverEncryptionKey;
  }

  public static byte[] randomKeyBytes() {
    byte byteArray[] = new byte[16];

    SecureRandom psn1;
    try {
      psn1 = SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException e) {
      log.error("Could not find SHA1PRNG: " + e.toString());
      throw new RuntimeException(e);
    }
    psn1.setSeed(psn1.nextLong());
    psn1.nextBytes(byteArray);

    return byteArray;
  }

  /**
   * Creates a psedorandom string
   *
   * @return Random String
   */
  public static String randomString() {
    String result = new String();

    byte byteArray[] = new byte[16];

    SecureRandom psn1 = null;

    try {
      psn1 = SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException e) {
      log.error("Could not find SHA1PRNG: " + e.toString());
      throw new RuntimeException(e);
    }

    psn1.setSeed(psn1.nextLong());
    psn1.nextBytes(byteArray);
    BigInteger bigInt = new BigInteger(byteArray);
    result = bigInt.toString();
    log.debug("Generated String = " + result);

    return result;
  }
}
