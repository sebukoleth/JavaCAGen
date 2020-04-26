package org.free.ca.line;

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

import org.free.ca.CertsGenOptions;
import picocli.CommandLine;

public class KeyFormatConverter implements CommandLine.ITypeConverter<String> {

    @Override
    public String convert(String value) throws Exception {
        if (CertsGenOptions.KEY_FORMATS.PKCS1.name().equalsIgnoreCase(value))
            return CertsGenOptions.KEY_FORMATS.PKCS1.name();
        else if (CertsGenOptions.KEY_FORMATS.PKCS8.name().equalsIgnoreCase(value))
            return CertsGenOptions.KEY_FORMATS.PKCS8.name();
        else
            throw new IllegalArgumentException("Keyformat value incorrect: \"" + value + "\"");
    }
}
