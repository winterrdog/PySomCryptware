# PySomCryptware
## Introduction
A simple but powerful ransomware to hone your red team skills. This is one of a hell of a program granny didn't tell you about. I developed this program for educational purposes for those who wanna develop or learn how ransomware works at heart. I didn't implement heavy tricks like, using `asymmetric encryption`, memory-resistant functions and algorithms for key-generation and others, in order to make my goal crystal-clear to learners. Hope you will like it.

## 📚 PREREQUISITES
* The `Python` interpreter should be installed. Linux users can use [this](https://command-not-found.com/python) while Windows and other OSes can follow [this](https://www.python.org/downloads/release/python-3107/). Any Python version from `3.6+` will work.
* `pip` should be installed. if not follow [this](https://command-not-found.com/pip) for Linux and others should follow [this](https://pip.pypa.io/en/stable/installation/#supported-methods)
## 🔧🔨 USAGE
1. Clone this repository( You can also just download it. )
```sh
    git clone https://github.com/winterrdog/PySomCryptware.git 
    cd PySomCryptware
```
2. Encryption is achieved like this: 
      - On Unix,
      ```sh 
      python ./main.py
    ``` 
     or 
     ```sh
     python ./main.py -a encrypt
    ```
     - On Windows( in `cmd` or `powershell` ), 
     ```powershell
     py ./main.py
     ``` 
     or 
     ```powershell
     py ./main.py -a encrypt
     ```
3. Decryption( reverse encryption ) is achieved like this: 
      - On Unix,
          ```sh
      python ./main.py -a decrypt
      ```
      - On Windows( in `cmd` or `powershell` ),
         ```powershell
      py ./main.py -a decrypt
      ```
## NOTE:
Only for educational purposes, man! I'm not responsible for your actions
and in case I forgot to explain something, please endeavor to read the code as it can explain a lot more than I can, don't be a `skiddie`. Go hard instead!
##  Contributions
They're always welcome with open hands as long as they're for the good of the community. You are also free to push this code further
