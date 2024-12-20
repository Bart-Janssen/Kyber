# Kyber
This repository is part of the
'Post-Quantum Cryptography on smart cards' by Bart Janssen at the
Open University, faculty of Management, Science and Technology.
Master Software Engineering.

## Purpose
The Kyber implementation of this repository is based on [KyberJCE](https://github.com/fisherstevenk/kyberJCE).
This repository is only used for verification and testing purposes
of the smart card [Kyber applet](https://github.com/Bart-Janssen/Applets/tree/main/applet/src/kyber).

## Reference implementation
The reference implementation is a copy of the KyberJCE 
implementation where DER encoding and the Java Security Provider
are removed. The reference implementation is mainly used for 
verification of the smart card implementation.

## Smart card implementation
The smart card implementation is an implementation of Kyber that 
is used for running on a host computer to verify its correctness
against the reference implementation for easy testing. This 
implementation contains some dummy functions to mask JavaCard API 
functions. The actual smart card implementation that is suitable
for JavaCard can be found [here](https://github.com/Bart-Janssen/Applets/tree/main/applet/src/kyber).