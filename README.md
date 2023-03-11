## Introduction


## Requirment
1. Intel SGX
2. Intel-SGX-SSL
3. OPENSSL
4. BOOST

## Build
1. build enclaves
    ```
    cd src/Enclave
    make
    ```
    There are two enclaves, EnclaveBudget and EnclaveCompute. 
2. build apps
    ```
    cd build && cmake ..
    make
    ```

## Data Compression
The original dataset can be found [here](http://ftp.1000genomes.ebi.ac.uk/vol1/ftp/phase1/analysis_results/integrated_call_sets/), which contains massive genome informations. The original files are too large to process, so we need to compress the files in the data prepocessing stage.
```
cd bin
./compress_vcf path_to_the_original_file
```
After this step, we will get several smaller files whose suffix is *.gwas* and a file named idList.txt which contains all *rs_ids*. These files can be found in directory *data*.

## Data Uploading
When uploading a file, the client encrypt the file, and send the encryption key to the EnclaveCompute and the privacy budget to the EnclaveBudget. EnclaveCompute can use the received key to decrypt the file and store all informations in a *map*.

When the termination (Ctrl^C) of server happens, it will seal the data(keys, budgets) in these two enclaves. When the server restarts, the unsealed data will be sent to these enclaves seperately.

## Data Processing
The client sends the data processing request, including parameters, to the server. Upon receiving a request, the EnclaveCompute finds the *fileNameHash* of the *rs_ids* and sends them to the EnclaveBudget to query whether it can process the data.

## A Simple Test
You can get help informations by running this:
```
cd bin && ./client -h
```
1. run the server
    ```
    cd bin
    ./server
    ```
2. upload files
    ```
    cd scripts
    ./upload.sh
    ```

3. process data
    ```
    ./process.sh
    ```
    results:
    ```
    lighthouse@VM-4-11-ubuntu:~/workspace/sgx/frog/scripts$ ./process.sh 
    SSLConnection:client successfully connect to <127.0.0.1:1666>
    LD:0 HWE:-1 CATT:0 FET:1
    SSLConnection:shutdown the SSL connection successfully.
    SSLConnection:client successfully connect to <127.0.0.1:1666>
    LD:0 HWE:0 CATT:0 FET:1
    SSLConnection:shutdown the SSL connection successfully.
    lighthouse@VM-4-11-ubuntu:~/workspace/sgx/frog/scripts$ 
    ```
    -1 means failure .
4. terminate and restart the server
5. process data again  
    we can get same results, that means the data in the enclaves are sealed and unsealed correctly.


## TODO
1. apply multi-thread programing  
    need to add locks in record in Enclaves
2. Remote Attestation and Local Attestation  have to be done
3. review the code, use smart pointers to manage dynamic memory
4. file deduplicated, for now hash of filename, hash of filepath + client id

