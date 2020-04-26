package org.free.ca.server;

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

import java.io.File;
import java.io.IOException;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.free.ca.CertsGenOptions;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;

import static org.free.ca.Entrypoint.*;
import static org.free.ca.Holder.*;
import org.free.ca.exceptions.CertificateGenerationException;

public class ServerCertsGenerator {

    private static final Logger LOGGER = LogManager.getLogger(ServerCertsGenerator.class);
    
    private final CertsGenOptions certsGenOptions;

    public ServerCertsGenerator(CertsGenOptions genOptions) {
        certsGenOptions = genOptions;
    }

    public void generateServerKeys(X500Name rootCertIssuer, PublicKey rootCaPublicKey, PrivateKey rootCaPrivateKey, Date startDate,
                                   Date endDate) throws CertificateGenerationException {
        LOGGER.info("Begin generating server certs");
        String serverCertsDir;
        if(certsGenOptions.getDomainNames().length > 0) { 
            serverCertsDir = certsGenOptions.getDomainNames()[0];
        } else if (certsGenOptions.getIpAddresses().length > 0) {
            serverCertsDir = certsGenOptions.getIpAddresses()[0];
        } else {
            throw new IllegalArgumentException("At least one domain name or IP address needs to be supplied");
        }
        LOGGER.info("Setting server cert CN to {}", serverCertsDir);
        if (!validateIPAddresses()) {
            throw new IllegalArgumentException("Illegal formatted IP address");
        }
        if (!validateDomainNames()) {
           throw new IllegalArgumentException("Invalid domain name format.");
        }
        serverCertsDir = serverCertsDir.replaceAll("\\*", "_");
        File serverCerts = new File(serverCertsDir);
        if (!serverCerts.exists()) {
            serverCerts.mkdirs();
        }
        LOGGER.info("Server certs will be written to {}", serverCertsDir);
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator= KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        } catch (NoSuchAlgorithmException nsae) {
            LOGGER.error("Unable to create key pair generator with algorithm {}", KEY_ALGORITHM, nsae);
            throw new CertificateGenerationException(nsae);
        } catch (NoSuchProviderException nsae) {
            LOGGER.error("Unable to find provider for creating keypair {}", BC_PROVIDER, nsae);
            throw new CertificateGenerationException(nsae);
        }
        // Generate a new KeyPair and sign it using the Root Cert Private Key
        // by generating a CSR (Certificate Signing Request)
        X500Name issuedCertSubject = new X500Name("CN=java-ca server-cert");
        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        KeyPair serverCertKeyPair = keyPairGenerator.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject,
                serverCertKeyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(certsGenOptions.getKeyAlgo()).setProvider(BC_PROVIDER);
        LOGGER.info("Done creating CSR for server certs");
        // Sign the new KeyPair with the root cert Private Key
        ContentSigner csrContentSigner;
        try {
            csrContentSigner = csrBuilder.build(rootCaPrivateKey);
        } catch (OperatorCreationException ex) {
            LOGGER.error("Unable to create CSR signer", ex);
            throw new CertificateGenerationException(ex);
        }
        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

        // Use the Signed KeyPair and CSR to generate an issued Certificate
        // Here serial number is randomly generated. In general, CAs use
        // a sequence to generate Serial number and avoid collisions
        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(rootCertIssuer, issuedCertSerialNum,
                startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

        JcaX509ExtensionUtils issuedCertExtUtils;
        try {
            issuedCertExtUtils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.error("Unable to use default algorithm to initialize X509 certificate extensions handler", ex);
            throw new CertificateGenerationException(ex);
        }

        try {
            // Add Extensions
            // Use BasicConstraints to say that this Cert is not a CA
            issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

            X509Certificate rootCert = readeCaCert(certsGenOptions.getRootCaCertName() + ".pem");

            // Add Issuer cert identifier as Extension
            issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));
            issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                    issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

            // Add intended key usage extension if needed
            issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature));
            ExtendedKeyUsage exKeyUsage = new ExtendedKeyUsage(new KeyPurposeId[] 
                                {KeyPurposeId.id_kp_clientAuth,  KeyPurposeId.id_kp_serverAuth});
            issuedCertBuilder.addExtension(Extension.extendedKeyUsage, false, exKeyUsage);

            List<GeneralName> genNamesList = new ArrayList<>();
            for (String dn : certsGenOptions.getDomainNames()) {
                genNamesList.add(new GeneralName(GeneralName.dNSName, dn.trim()));
            }
            for(String ip : certsGenOptions.getIpAddresses()) {
                genNamesList.add(new GeneralName(GeneralName.iPAddress, ip.trim()));
            }
            // Add DNS names and IP addresses to be used for SSL
            issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, 
                    new DERSequence(genNamesList.toArray(new GeneralName[genNamesList.size()])));

        } catch (CertIOException ce) {
            LOGGER.error("Error configuring extensions for server cert", ce);
            throw new CertificateGenerationException(ce);
        } catch (IOException | CertificateException ioe) {
            LOGGER.error("Unable to read CA cert {}.", certsGenOptions.getRootCaCertName() + ".pem", ioe);
            throw new CertificateGenerationException(ioe);
        }
        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
        
        X509Certificate issuedCert;
        try {
            issuedCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);
        } catch (CertificateException ex) {
            LOGGER.error("Unable to get X509Cert from holder", ex);
            throw new CertificateGenerationException(ex);
        }

        try {
            // Verify the issued cert signature against the root (issuer) cert
            issuedCert.verify(rootCaPublicKey, BC_PROVIDER);
        } catch (CertificateException ex) {
            LOGGER.error("Error verifying server cert against CA public key", ex);
            throw new CertificateGenerationException(ex);
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.error("Unable to use {} with parsed algorithm", BC_PROVIDER, ex);
            throw new CertificateGenerationException(ex);
        } catch (InvalidKeyException ex) {
            LOGGER.error("Invalid key used", ex);
            throw new CertificateGenerationException(ex);
        } catch (NoSuchProviderException ex) {
            LOGGER.error("Unable to use requested provider {}", BC_PROVIDER, ex);
            throw new CertificateGenerationException(ex);
        } catch (SignatureException ex) {
            LOGGER.error("Unable to verify signature", ex);
            throw new CertificateGenerationException(ex);
        }
        LOGGER.info("Done creating server certs. Now to write them out to files.");
        String serverCertFile = serverCertsDir + File.separator + "cert.pem";
        String serverPrivateKeyFile = serverCertsDir + File.separator + "key.pem";
        try {
            writeCertToPEMFile(issuedCert, serverCertFile);
            writePrivateKeyToPem(serverCertKeyPair.getPrivate(), serverPrivateKeyFile, 
                certsGenOptions.getKeyFormat());
        } catch (IOException ioe) {
            LOGGER.error("Unable to write out the server cert and private key files", ioe);
            throw new CertificateGenerationException(ioe);
        }
        LOGGER.info("Done writing out server certs to {} and {}", serverCertFile, serverPrivateKeyFile);
    }
    
    private boolean validateIPAddresses() {
        if (certsGenOptions.getIpAddresses().length > 0) {
            for (String ip : certsGenOptions.getIpAddresses()) {
                if(!InetAddressValidator.getInstance().isValid(ip.trim())) {
                    LOGGER.error("Invalid IP address format used {}. Must be IPv4 or IPv6 IP address.", ip);
                    return false;
                }
            }
        }
        return true;
    }
    
    private boolean validateDomainNames() {
        Pattern domainNamePatter = Pattern.compile("^[A-Za-z0-9.*-]+$");
        if (certsGenOptions.getDomainNames().length > 0) {
            for (String ip : certsGenOptions.getDomainNames()) {
                Matcher domainMatch = domainNamePatter.matcher(ip.trim());
                if(!domainMatch.matches()) {
                    LOGGER.error("Invalid domain name format used {}.", ip.trim());
                    return false;
                }
            }
        }
        return true;
    }
}
