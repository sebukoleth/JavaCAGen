**Java CA Gen**
This is a small Java program using Bouncycastle APIs to create a root CA private key and certificate, then use it to sign a server certificate that can then be used on an SSL server.
Heavily draws inspiration from [minica](https://github.com/jsha/minica)


---

## Server certs

The certificate will contain a list of DNS names and/or IP addresses from the command line flags. The key and certificate are placed in a new directory whose name is chosen as the first domain name from the certificate, or the first IP address if no domain names are present. It will not overwrite existing keys or certificates.

---

## Installation

1. Clone the repository
2. On a commandline issue `./gradlew clean build`
 
## Usage
`java -jar java-ca-nb.jar --domains localhost,mydomain.org`
