package com.example.taskmanagerauth.service;

import com.example.taskmanagerauth.entity.Mfa;
import com.example.taskmanagerauth.entity.User;
import com.example.taskmanagerauth.exception.server.MfaNotEnabledException;
import com.example.taskmanagerauth.exception.server.TotpInvalidException;
import com.example.taskmanagerauth.exception.server.TotpNotProvidedException;
import com.google.crypto.tink.*;
import com.google.crypto.tink.aead.AeadConfig;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

@Service
public class MfaService {

    private final UserService userService;

    private final GoogleAuthenticator authenticator = new GoogleAuthenticator();
    private final KeysetHandle mfaKey;

    @Autowired
    public MfaService(
            @Value("${mfa.secret}") String mfaSecretKeySet,
            UserService userService
    ) {
        this.userService = userService;
        mfaKey = getMfaKey(mfaSecretKeySet);
    }

    /**
     * Get the Base64 encoded key from the environment to be used for decoding/encoding.
     * @param mfaKeySet Base64 encoded keyset, loaded from GitHub secrets
     * @return (KeysetHandle) The object representation of the Base64 imported string
     */
    private KeysetHandle getMfaKey(String mfaKeySet) {

        try {

            AeadConfig.register();

            byte[] keysetBytes = Base64.getDecoder().decode(mfaKeySet);

            try (ByteArrayInputStream input = new ByteArrayInputStream(keysetBytes)) {

                return CleartextKeysetHandle.read(
                        BinaryKeysetReader.withInputStream(input)
                );

            }

        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * Get the time-based one time password as a number
     * @param totp String representation of the TOTP code
     * @return (int) Integer representation of the TOTP code
     */
    private int getTotp(String totp) {

        if (totp == null || totp.isEmpty()) {
            throw new TotpNotProvidedException("One time password not provided.");
        }

        int totp_num;

        try {
            totp_num = Integer.parseInt(totp);
        } catch (NumberFormatException exception) {
            throw new TotpNotProvidedException("One time password not provided.");
        }

        return totp_num;

    }

    public boolean hasMfaEnabled(User user) {
        return user.getMfa().getMfaEnabled();
    }

    /**
     * Encrypt using mfaKey
     * @param key (String) A key to be encrypted
     * @return The encrypted, base64 representation
     */
    public String encrypt(String key) {

        try {
            Aead aead = mfaKey.getPrimitive(RegistryConfiguration.get(), Aead.class);

            byte[] stringAsBytes = key.getBytes(StandardCharsets.UTF_8);
            byte[] cipherText = aead.encrypt(stringAsBytes, "taskmanagerauth".getBytes());

            return Base64.getEncoder().encodeToString(cipherText);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * Decrypt using mfaKey
     * @param encryptedKey (String) An encrypted key
     * @return The decrypted, String representation
     */
    public String decrypt(String encryptedKey) {

        try {
            Aead aead = mfaKey.getPrimitive(RegistryConfiguration.get(), Aead.class);

            byte[] cipherText = Base64.getDecoder().decode(encryptedKey);
            byte[] decrypted = aead.decrypt(cipherText, "taskmanagerauth".getBytes());

            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * Generate the TOTP code for usage on frontend
     * @return (String) The otpauth code
     */
    public String generateMfaCode() {

        User user = userService.loadUserByContext();
        return "otpauth://totp/TaskManagerAuth:" + user.getId() + "?secret=" + decrypt(user.getMfa().getMfaSecretKey()) + "&issuer=TaskManagerAuth\n";

    }

    /**
     * Validate a time-based one time password
     * @param totp One time password
     * @param user User
     */
    public void validatePassword(String totp, User user) {

        if (totp.isEmpty()) {
            throw new TotpNotProvidedException("Please provide a TOTP code.");
        }

        int totp_num = getTotp(totp);

        if (!hasMfaEnabled(user)) {
            throw new MfaNotEnabledException("Mfa not enabled.");
        }

        if (!authenticator.authorize(decrypt(user.getMfa().getMfaSecretKey()), totp_num)) {
            throw new TotpInvalidException("Incorrect TOTP provided.");
        }

    }

    /**
     * Using a TOTP code the user provides, activate the user's MFA if correct
     * @param totp Code provided
     * @param userDetails The user
     */
    public void setupMfa(String totp, UserDetails userDetails) {

        int totp_num = getTotp(totp);
        User user = userService.getUserById(userDetails);

        if (!authenticator.authorize(decrypt(user.getMfa().getMfaSecretKey()), totp_num)) {
            throw new TotpInvalidException("Incorrect TOTP provided.");
        }

        user.getMfa().setMfaEnabled(true);

        userService.saveUser(user);

    }

    /**
     * Create a row in the mfa table
     * @param user The user
     */
    public void instantiateMfaForUser(User user) {

        GoogleAuthenticatorKey key = authenticator.createCredentials();
        Mfa mfa = new Mfa(null, user, false, encrypt(key.getKey()));
        user.setMfa(mfa);

    }

}
