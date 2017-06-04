[![Java Version](http://img.shields.io/badge/Java-1.8-blue.svg)](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)
[![Download](https://api.bintray.com/packages/julianghionoiu/maven/kms-jwt/images/download.svg)](https://bintray.com/julianghionoiu/maven/kms-jwt/_latestVersion)
[![Codeship Status for julianghionoiu/kms-jwt](https://img.shields.io/codeship/5a667980-2af8-0135-70bf-3ade48bf5979/master.svg)](https://codeship.com/projects/224001)
[![Coverage Status](https://coveralls.io/repos/github/julianghionoiu/kms-jwt/badge.svg?branch=master)](https://coveralls.io/github/julianghionoiu/kms-jwt?branch=master)

## Usage

TODO


## Development

Might need Install Java Cryptography Extension?
https://cwiki.apache.org/confluence/display/STONEHENGE/Installing+Java+Cryptography+Extension+%28JCE%29+Unlimited+Strength+Jurisdiction+Policy+Files+6


### Problems and solutions

On MAC, if Encoder spends around 5 seconds initialising, have a look at this:
https://stackoverflow.com/questions/25321187/java-mac-getinstance-for-hmacsha1-slow