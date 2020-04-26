package org.free.ca.root;

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

import java.io.IOException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.free.ca.CertsGenOptions;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

import static org.free.ca.Entrypoint.*;
import static org.free.ca.Holder.*;
import org.free.ca.server.ServerCertsGenerator;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.free.ca.exceptions.CertificateGenerationException;

public class RootCAGenerator {

    private static final Logger LOGGER = LogManager.getLogger(RootCAGenerator.class);
    
    private CertsGenOptions certsGenOptions;

    public RootCAGenerator(CertsGenOptions genOptions) {
        certsGenOptions = genOptions;
    }

    public void generateRootCerts(Date startDate, Date endDate) throws CertificateGenerationException {
        LOGGER.info("Begin generating root CA certs");
        // Initialize a new KeyPair generator
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        } catch (NoSuchAlgorithmException nsae) {
            LOGGER.error("Unable to create key pair generator with algorithm {}", KEY_ALGORITHM, nsae);
            throw new CertificateGenerationException(nsae);
        } catch (NoSuchProviderException nsae) {
            LOGGER.error("Unable to find provider for creating keypair {}", BC_PROVIDER, nsae);
            throw new CertificateGenerationException(nsae);
        }
        keyPairGenerator.initialize(certsGenOptions.getKeySize());

        // First step is to create a root certificate
        // First Generate a KeyPair,
        // then a random serial number
        // then generate a certificate using the KeyPair
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // Issued By and Issued To same for root certificate
        X500Name rootCertIssuer = new X500Name("CN=java-ca root CA");
        ContentSigner rootCertContentSigner;
        try {
            rootCertContentSigner = new JcaContentSignerBuilder(
                certsGenOptions.getKeyAlgo()).setProvider(BC_PROVIDER).build(rootKeyPair.getPrivate());
        } catch (OperatorCreationException oce) {
            LOGGER.error("Unable to create operator", oce);
            throw new CertificateGenerationException(oce);
        }
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(
                rootCertIssuer, rootSerialNum, startDate, endDate, rootCertIssuer, rootKeyPair.getPublic());

        // Add Extensions
        // A BasicConstraint to mark root certificate as CA certificate
        JcaX509ExtensionUtils rootCertExtUtils;
        try {
            rootCertExtUtils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException nsae) {
            LOGGER.error("Unable to create JCA extensions handler", nsae);
            throw new CertificateGenerationException(nsae);
        }
        
        try {
            rootCertBuilder.addExtension(Extension.basicConstraints, true,
                    new BasicConstraints(true));
            rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                    rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));
            rootCertBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    rootCertExtUtils.createAuthorityKeyIdentifier(rootKeyPair.getPublic()));
            KeyUsage ku = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
            rootCertBuilder.addExtension(Extension.keyUsage, false, ku);
            ExtendedKeyUsage exKeyUsage = new ExtendedKeyUsage(new KeyPurposeId[] 
                                {KeyPurposeId.id_kp_clientAuth,  KeyPurposeId.id_kp_serverAuth});
            rootCertBuilder.addExtension(Extension.extendedKeyUsage, false, exKeyUsage);
        } catch (CertIOException ce) {
            LOGGER.error("Error configuring extensions for root cert", ce);
            throw new CertificateGenerationException(ce);
        }
        LOGGER.info("Done creating root CA certs. Writing them out to {} and {}",
                certsGenOptions.getRootCaCertName() + ".pem", certsGenOptions.getRootCaCertName()+ "-key.pem");
        // Create a cert holder and export to X509Certificate
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        try {
            X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(rootCertHolder);
            writeCertToPEMFile(rootCert, certsGenOptions.getRootCaCertName() + ".pem");
            writePrivateKeyToPem(rootKeyPair.getPrivate(), certsGenOptions.getRootCaCertName()+ "-key.pem", certsGenOptions.getKeyFormat());
        } catch (CertificateException ce) {
            LOGGER.error("Error creating root cert", ce);
            throw new CertificateGenerationException(ce);
        } catch (IOException ioe) {
            LOGGER.error("Unable to write out the root CA cert and private key files", ioe);
            throw new CertificateGenerationException(ioe);
        }
        LOGGER.info("Done creating root CA private key and cert files. Starting on server certs.");
        new ServerCertsGenerator(certsGenOptions).generateServerKeys(rootCertIssuer, 
            rootKeyPair.getPublic(), rootKeyPair.getPrivate(), startDate, endDate);
    }

}
