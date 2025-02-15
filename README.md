# KupynaDS
A command-line tool to digitally sign files using a combination of two Ukrainian cryptographic standards, DSTU 4145-2002 (elliptic curve digital signature) and DSTU 7564:2014 (hash function).
The main idea of the project is to prove that Ukraine needs neither Soviet nor Russian cryptographic standards.

For that purpose, the library code, necessary to use National Standards of Ukraine DSTU 4145 and DSTU 7564, was included.

For the purpose of generating nonces for DSTU 4145 digital signatures, there had been a CSPRNG, implemented with use of a Soviet cipher according to Appendix A of DSTU 4145.
It was replaced with reading random numbers from the operating system directly.

A limit was removed which prevents from signing data of lengths other than 256 bits.

Special thanks to PryvatBank for Cryptonite cryptographic library source code. https://github.com/privat-it/cryptonite

Update 11 Feb 2025: I have just noticed that there is a fork of Cryptonite in active development: https://github.com/specinfo-ua/UAPKI.