package org.free.ca;

/*
 * Copyright [2020] Sebu Koleth Thomas

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;

import static org.free.ca.Entrypoint.BC_PROVIDER;

public interface Holder {

    static X509Certificate readeCaCert(String fileName) throws IOException, CertificateException {
        try (FileReader fr = new FileReader(fileName);
            PEMParser parser = new PEMParser(fr)) {
            X509CertificateHolder certificateHolder = ((X509CertificateHolder) parser.readObject());
            return new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate(certificateHolder);
        }
    }

    static void writeCertToPEMFile(Certificate certificate, String fileName) throws IOException {
        try (FileWriter fos = new FileWriter(fileName);
             JcaPEMWriter pemWriter = new JcaPEMWriter(fos)) {
            pemWriter.writeObject(certificate);
        }
    }

    static void exportKeyPairToKeystoreFile(KeyPair keyPair, Certificate certificate, String alias, String fileName,
                                            String storeType, String storePass) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
        sslKeyStore.load(null, null);
        sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(),null, new Certificate[]{certificate});
        FileOutputStream keyStoreOs = new FileOutputStream(fileName);
        sslKeyStore.store(keyStoreOs, storePass.toCharArray());
    }

    static void writePrivateKeyToPem(PrivateKey pk, String fileName, String pkcsVer) throws IOException {
        try (FileWriter fos = new FileWriter(fileName);
             JcaPEMWriter pemWriter = new JcaPEMWriter(fos)) {
            if("PKCS8".equalsIgnoreCase(pkcsVer)) {
                //unencrypted form of PKCS#8 file
                JcaPKCS8Generator pkcs8Gen = new JcaPKCS8Generator(pk, null);
                PemObject pkcs8Key = pkcs8Gen.generate();
                pemWriter.writeObject(pkcs8Key);
            } else {
                pemWriter.writeObject(pk);
            }
        }
    }

    static void writePrivateKeyToEncryptedPem(PrivateKey pk, String fileName, String pkcsVer, String password) 
            throws IOException, OperatorCreationException {
        try (FileWriter fos = new FileWriter(fileName);
             JcaPEMWriter pemWriter = new JcaPEMWriter(fos)) {
            if("PKCS8".equalsIgnoreCase(pkcsVer)) {
                JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_RC2_128);
                encryptorBuilder.setRandom(new SecureRandom());
                encryptorBuilder.setPasssword(password.toCharArray());
                OutputEncryptor encryptor = encryptorBuilder.build();
                JcaPKCS8Generator pkcs8Gen = new JcaPKCS8Generator(pk, encryptor);
                PemObject pkcs8Key = pkcs8Gen.generate();
                pemWriter.writeObject(pkcs8Key);
            } else {
                pemWriter.writeObject(pk);
            }
        }
    }
}
