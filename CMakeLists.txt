cmake_minimum_required(VERSION 3.16)
project(frog)

set(CMAKE_CXX_STANDARD 20)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

find_package(Boost 1.36.0 REQUIRED COMPONENTS thread system serialization iostreams)
find_package(OpenSSL REQUIRED)
if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    link_directories(${Boost_LIBRARY_DIRS})
else ()
    message(FATAL_ERROR, "Cannot find Boost library")
endif ()
if (OpenSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    link_directories(${OPENSSL_LIBRARY_DIR})
else ()
    message(FATAL_ERROR, "Cannot find OpenSSL library")
endif ()

set(SGX_SDK /opt/intel/sgxsdk)
set(SGXSSL_TRUSTED_LIB_PATH /opt/intel/sgxssl/lib64)

include_directories(include 
                    src/Enclave/Include 
                    src/Enclave/EnclaveBudget 
                    src/Enclave/EnclaveCompute 
                    ${SGX_SDK}/include)

link_directories(${SGX_SDK}/lib64)
link_directories(${SGXSSL_TRUSTED_LIB_PATH})

add_executable(client 
                src/app/client.cc 
                src/comm/CryptoPrimitive.cc 
                src/comm/SSLConnection.cc 
                src/client/FileSender.cc 
                src/client/OrderSender.cc 
                src/comm/json11.cc)
target_link_libraries(client OpenSSL::SSL)

add_executable(server 
                src/app/server.cc 
                src/comm/SSLConnection.cc 
                src/server/ServerOptThread.cc 
                src/server/FileReceiver.cc 
                src/server/OrderReceiver.cc 
                src/server/GWASExecutor.cc
                src/comm/json11.cc 
                src/Enclave/EnclaveBudget/EnclaveBudget_u.c 
                src/Enclave/EnclaveCompute/EnclaveCompute_u.c 
                src/server/UntrustedEnclaveMessageExchange.cc
                src/comm/CryptoPrimitive.cc)
                
target_link_libraries(server OpenSSL::SSL Boost::thread)
target_link_libraries(server sgx_urts_sim sgx_uae_service_sim sgx_usgxssl)

add_executable(compress_vcf
                src/app/compress_vcf.cc)