Diceros
===============

Diceros is a sub-project of Rhino project which focus on providing a hardware accelerated JCE provider. Initial effort include:
* AES-NI enabled AES/CTR/NOPADDING encryption/decryption support
* Hardware based true random generator (DRNG)

Diceros is not a full featured JCE provider yet for now, but we will make continuous effort towards that goal. You can download 
the source code and follow the instruction to build it, we have test the functionality in OpenJDK 7.

### Quick Start

https://github.com/intel-hadoop/diceros/wiki/Quick-Start

### Prerequisite
#### Hardware prerequisite:   
* Intel® Digital Random Number Generator (DRNG)   
* AES-NI

#### Software prerequisite:   
* <p>openssl-1.0.1c or above(just test openssl-1.0.1e);  </p> 
* <p>yasm-1.2.0 </p>
* <p>openjdk7;    </p>
* <p>add `libdiceros.so` and `libaesmb.so` (which are generated after build) to the environment variable `java.library.path`; </p>
* <p>add `diceros-1.0.0.jar`(which is generated after build) to the classpath; </p>

### Build 
`mvn package`

### Validate
`mvn test`

### Download Binary Releases
https://github.com/intel-hadoop/diceros/releases

### Deploy
#### Static deploy:   
Add line `security.provider.10=com.intel.diceros.provider.DicerosProvider` in file `\<java-home\>\lib\security\java.security`

#### Dynamic deploy:   
Add the following line `Security.addProvider(new com.intel.diceros.provider.DicerosProvider());`    
before calling method `SecureRandom.getInstace()` or `Cipher.getInstance()`.

### Troubleshooting
https://github.com/intel-hadoop/diceros/wiki/Troubleshooting


### Algorithm Validation Test
The algorithm validation of diceros uses The Advanced Encryption Standard Algorithm Validation Suite(AESAVS)to verify.(see AESSAV detail from http://http//csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf).The AESAVS is designed to perform automated testing on Implementations Under Test.
Diceros use the Known Answer Test(KAT) to validation of the implementation of the Advanced Encryption Standard algorithm. The validate command:
`mvn test -Dtest=com.intel.diceros.test.aes.AESKatTest`

### Performance Test
Diceros performance testing use the nice tool supported from OpenJDK, Java Microbenchmark Harness(JMH). JMH is a java harness for building, running and analyzing nano/micro/milli/macro benchmarks written in java and other language targeting the JVM.(see detail from http://openjdk.java.net/projects/code-tools/jmh/)
#### How it work with Diceros performance testing ?
Software prerequisite:
* apply the performance path to diceros project. the patch address is xxx, using the following command:
* `cd the diceors project directory`
* `patch -p1 < patch(you download)
* `mvn install `
performance testing usage:
java -jar target/microbenchmarks.jar .*encryptPerfTest(or .*decryptPerfTest or *.cryptPerfTest -->test for both) -wi 20 -i 30 -f 1 -p provider=${provider} -p mode=${mode} -p directBuffer=${useBuffer} -p buffer_size=${buffer_size} -p sizeUnit=${sizeUnit}
-wi number of warmup iterations
-i number of benchmarked iterations, use 10 or more to get a good idea
-f How many times to forks a single benchmark
-p buffer_size=xxx(default 128)
-p sizeUnit=xx(default KB)
-p provider=xxx(default SunJCE)
-p mode=xxx(default AES/CTR/NoPadding)
-p directBuffer=xxx(default false)
(see the performance testing detail from http://)


