# UnLinkable-PCS (ul-PCS)


Policy-compliant signature (PCS) schemes are enhanced signature schemes that enable policy enforcement (a joint predicate on sender and receiver attributes) via signatures while ensuring full privacy of each user's attributes. Unlinkable PCS (ul-PCS) further adds the capability that a user can refresh its public key (without the need to contact a credential issuer) to break any link to their previous activities.

This repository contains a prototype, that is, an implementation of PCS (based on policies specified by inner-product relations), and several implementations for ul-PCS (for different policy classes) proposed in [1]. While a lot of effort has gone into this work, being a prototype means that the code should be used for testing purposes only, and should not be used in a productive environment without further external and professional audits. 

The structure of this repository is as follows:

* `Generic_ul-PCS`: Python code to emulate the proposed Generic UL-PCS scheme. Please execute test.py for testing.
	- Acc.py: Python code to emulate the accumulator scheme.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- Bulletproof.py: Python code to emulate the Range-proof.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- matmath.py: Python code to emulate some basic math operation on matrices.
	- OT12.py: Python code to emulate OT12 PO-PE scheme.
	- Pedersen.py: Python code to emulate a Pedersen Commitment.
  - PRF.py: Python code to emulate the Dodis-Yampolskiy PRF.
  - Sigma.py: Python code to emulate the described Sigma protocols.
  - SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
  - SPSEQ.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature on equivalence classes.
  - test.py: To test the code.

* `PCS`: Python code to emulate the Generic Standard PCS scheme proposed by Badertscher, Matt and Waldner (TCC’21). Please execute test.py for testing.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- matmath.py: Python code to emulate some basic math operation on matrices.
	- OT12.py: Python code to emulate OT12 PO-PE scheme.
	- SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
	- test.py: To test the code.

* `RBAC_ul-PCS`: Python code to emulate the proposed Role-based UL-PCS scheme. Please execute test.py for testing.
	- Acc.py: Python code to emulate the accumulator scheme.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- Bulletproof.py: Python code to emulate the Range-proof.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- Pedersen.py: Python code to emulate a Pedersen Commitment.
	- policy.py: Python code to emulate a role-based policy maker algorithm.
  - PRF.py: Python code to emulate the Dodis-Yampolskiy PRF.
  - Sigma.py: Python code to emulate the described Sigma protocols.
  - SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
  - SPSEQ.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature on equivalence classes.
  - test.py: To test the code.
  
* `ul-PCS_with_SP`: Python code to emulate the proposed UL-PCS scheme with Separable policies. Please execute test.py for testing.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- Bulletproof.py: Python code to emulate the Range-proof.
	- ElGamal.py: Python code to emulate the ElGamal encryption.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- Pedersen.py: Python code to emulate a Pedersen Commitment.
	- policy.py: Python code to emulate a role-based policy maker algorithm.
  	- PRF.py: Python code to emulate the Dodis-Yampolskiy PRF.
  	- Sigma.py: Python code to emulate the described Sigma protocols.
	- SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
	- test.py: To test the code.


## Instruction for Ubuntu 22.04
Clone the repo via:

```
git clone https://github.com/ul-PCS/UnlinkablePCS.git
```

And then change your directory to:
```
cd UnlinkablePCS/
```

### Prerequisite Packages:
The dependencies and compatibility requirements on various existing libraries to run the prototype are quite involved. We recommend to use Docker to obtain a consistent execution environment (though the runtimes might be slower compared to a direct execution). Install Docker and then run the following command to build the docker container:

```
docker build -t ulpcs .
```

### Testing the Prototype:

To see the prototype in action, you can run the simple test files for any of the four implemented constructions as follows:

**Original PCS**

Single test:
```
docker run ulpcs python3 /app/PCS/test.py n
```
where n is the number of attributes and must be an integer, e.g. 5.

Full test*:
```
docker run ulpcs python3 /app/PCS/full_benchmark.py #begin $end #jump #iterations
```
Where begin represents the minimum number of attributes and end represents the maximum number of attributes. The jump variable specifies the jump in number of attributes, and iterations is the average of the selected iteration value. In the paper, we reported the following setting: begin=5 to end=50, jump=5 and iteration=100.

**Generic ul-PCS**

Single Test:

```
docker run ulpcs python3 /app/Generic/test.py n
```
Full Test*:

```
docker run ulpcs python3 /app/Generic/full_benchmark.py #begin $end #jump #iterations
```

**RBAC ul-PCS**

Single Test:

```
docker run ulpcs python3 /app/RBAC/test.py n
```
Full Test*:

```
docker run ulpcs python3 /app/RBAC/full_benchmark.py #begin $end #jump #iterations
```

**ul-PCS with Seperable Policies**

Single Test:

```
docker run ulpcs python3 /app/SP/test.py n
```
Full test*:
```
docker run ulpcs python3 /app/SP/full_benchmark.py #begin $end #jump #iterations
```

*Once any full test is run, the xlsx-file with the statistics can be retrieved. For example, first find the container ID via:

```
docker ps -a
```
Then copy the respective xlsx-file to the local machine, for example:

```
docker cp #Container_ID:/Generic.xlsx .
```


References:

[1] Badertscher, Christian, Mahdi Sedaghat, and Hendrik Waldner. "Fine-Grained Accountable Privacy via Unlinkable Policy-Compliant Signatures." To appear at PETS 2024.