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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.free.ca.root.RootCAGenerator;
import picocli.CommandLine;

import java.security.Security;
import java.util.Calendar;
import java.util.Date;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Entrypoint {

    private static final Logger LOGGER = LogManager.getLogger(Entrypoint.class);
    public static final String BC_PROVIDER = "BC";
    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static void main(String [] arg) {
        Security.addProvider(new BouncyCastleProvider());
        CertsGenOptions certsGenOptions = new CertsGenOptions();
        CommandLine.ParseResult options = new CommandLine(certsGenOptions).parseArgs(arg);
        try {
            // Setup start date to yesterday and end date for 2 years validity
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.DATE, -1);
            Date startDate = calendar.getTime();

            calendar.add(Calendar.YEAR, 2);
            Date endDate = calendar.getTime();
            new RootCAGenerator(certsGenOptions).generateRootCerts(startDate, endDate);
        } catch (Exception e) {
            LOGGER.error("Unable to generate certificates", e);
            System.exit(-1);
        }
    }
}
