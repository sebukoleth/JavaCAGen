**Java CA Gen**
This is a small Java program using Bouncycastle APIs to create a root CA private key and certificate, then use it to sign a server certificate that can then be used on an SSL server.

### Why was this written
When developing microservices that need 1-way or 2-way SSL the usual advice is to use self-signed SSL certificates. But this causes problem when
clients try to conenct to it. Now you are left the dirty job of subverting the server SSL certificate verification by the client SSL socket layer.
Leave alone the complex nature, this can also lead to security holes when development-level trust somehow gets into deployed instanes of the microservice..
So here we are generating actual certificates that are signed by a local CA.

## Licensed under Apache 2.0 license

---

## Server certs

The certificate will contain a list of DNS names and/or IP addresses from the command line flags. The key and certificate are placed in a new directory whose name is chosen as the first domain name from the certificate, or the first IP address if no domain names are present.

---

## Installation

1. Clone the repository
2. On a commandline issue `./gradlew clean build`
3. The uberjar will get built under $PROJECT_HOME/build/libs
 
## Usage
`java -jar ca-gen.jar --domains localhost,mydomain.org`
