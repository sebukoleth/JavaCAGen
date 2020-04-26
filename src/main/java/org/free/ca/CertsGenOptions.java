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

import lombok.Getter;
import org.free.ca.line.KeyFormatConverter;
import picocli.CommandLine;

import java.util.ArrayList;
import java.util.Arrays;
import lombok.NoArgsConstructor;
import static org.free.ca.Entrypoint.SIGNATURE_ALGORITHM;

@Getter
@NoArgsConstructor
public class CertsGenOptions {

    public enum KEY_FORMATS {PKCS1, PKCS8}
    static class KeyFormats extends ArrayList<String> {
        KeyFormats() { super(Arrays.asList(KEY_FORMATS.PKCS1.name(), KEY_FORMATS.PKCS8.name())); }
    }

    @CommandLine.Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    @CommandLine.Option(names = "--ca-cert", defaultValue = "java-ca", description =
            "Root certificate filename, PEM encoded(default: ${DEFAULT-VALUE})")
    private String rootCaCertName;

    @CommandLine.Option(names = "--domains", defaultValue = "localhost",
            description = "Comma separated domain names to include as Server Alternative Names(default: ${DEFAULT-VALUE})",
            split = ",")
    private String[] domainNames;

    @CommandLine.Option(names = "--ip-addresses", defaultValue = "127.0.0.1",
            description = "Comma separated IP addresses to include as Server Alternative Names(default: ${DEFAULT-VALUE})",
            split = ",")
    private String[] ipAddresses;

    @CommandLine.Option(names = "--key-format", defaultValue = "PKCS1",
            description = "Format to be used to write out private keys. (default: ${DEFAULT-VALUE})",
            converter = KeyFormatConverter.class)
    private String keyFormat;
    
    @CommandLine.Option(names = "--key-algo", defaultValue = SIGNATURE_ALGORITHM,
            description = "Algorithm to be used for the keys. (default: ${DEFAULT-VALUE})")
    private String keyAlgo;

    @CommandLine.Option(names = "--key-size", defaultValue = "2048",
            description = "Size of the key (default: ${DEFAULT-VALUE})")
    private int keySize;

}
