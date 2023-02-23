# TSSE
This is the TSSE tool's manual. TSSE is a symbol execution tool that is a combination of dynamic detection technology and static detection technology to complete the detection of cross-contract vulnerability. The static detection technology mainly uses [SLITHER](https://github.com/crytic/slither) as an intermediate language to collect warnings; based on the prototype tool [Mantiore](https://github.com/trailofbits/manticore), the call context switching, global storage and other practices in cross-contract calls realized by program instrumentation to ensure the accuracy and effectiveness of the symbol execution path searching process.


## Usage

You can use TSSE via the Command-Line Interface (CLI).

If you have a Smart Contract written in Solidity and you want to search only for Reentrancy vulnerabilities you can type:
```bash
$ python3 tool_reentrancy.py filename
```


## Dependencies

* [manticore](https://github.com/trailofbits/manticore/releases/tag/0.3.4)
* [slither](https://github.com/crytic/slither/releases/tag/0.7.1)
* [crytic-compile](https://github.com/crytic/crytic-compile)
* [z3-solver](https://pypi.org/project/z3-solver/)
* [pyevmasm](https://pypi.org/project/pyevmasm/)
* [python3](https://www.python.org/downloads/)
* [solidity_parser](https://pypi.org/project/solidity-parser/)
* [z3-solver](https://pypi.org/project/z3-solver/)


You can use the requirements.txt file to install all dependencies via:
```bash
$ pip install -r requirements.txt
```

or create a python environment:
```bash
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

## Detected Vulnerabilities

TSSE supports five types of vulnerability detection: Integer Overflow or Underflow (IO/U), Ether Leaking (EL), Reentrancy (RE),
Suicidal (SC), Timestamp dependency (TD). They are mainly based on the [SWC Registry](https://swcregistry.io/). The documents describing these five types of vulnerability are as follows:

* [Integer Overflow or Underflow (IO/U)](https://swcregistry.io/docs/SWC-101)
* [Reentrancy (RE)](https://swcregistry.io/docs/SWC-107)
* [Timestamp dependency (TD)](https://swcregistry.io/docs/SWC-116)
* [Suicidal (SC)](https://swcregistry.io/docs/SWC-106)
* [Ether Leaking (EL)](https://swcregistry.io/docs/SWC-104)


# Results

A sample output document is in the example-output folder

# License

TSSE is licensed and distributed under the AGPL-3.0 (AGPLv3) License