// author: https://t.me/biernus
#include "secp256k1.cuh"
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <stdexcept>
#include <sstream>
#include <cstdint>
#include <fstream>
#include <stdint.h>
#include <curand_kernel.h>
#include <algorithm>
#include <random>
#include <inttypes.h>
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#include <chrono>
#pragma once

#define HEX_LENGTH 64
__constant__ char hex_inc_table[16] = {'1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','0'};

__device__ __forceinline__ char hex_increment(char c) {
    if (c >= '0' && c <= '9') return hex_inc_table[c - '0'];
    if (c >= 'a' && c <= 'f') return hex_inc_table[c - 'a' + 10];
    if (c >= 'A' && c <= 'F') return hex_inc_table[c - 'A' + 10];
    return c;
}

__device__ __host__ __forceinline__ uint8_t hex_char_to_byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

// Convert hex string to bytes
__device__ __host__ __device__ void hex_string_to_bytes(const char* hex_str, uint8_t* bytes, int num_bytes) {
    #pragma unroll 8
    for (int i = 0; i < num_bytes; i++) {
        bytes[i] = (hex_char_to_byte(hex_str[i * 2]) << 4) | 
                   hex_char_to_byte(hex_str[i * 2 + 1]);
    }
}


// Convert hex string to BigInt - optimized
__device__ __host__ void hex_to_bigint(const char* hex_str, BigInt* bigint) {
    // Initialize all data to 0
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        bigint->data[i] = 0;
    }
    
    int len = 0;
    while (hex_str[len] != '\0' && len < 64) len++;
    
    // Process hex string from right to left
    int word_idx = 0;
    int bit_offset = 0;
    
    for (int i = len - 1; i >= 0 && word_idx < 8; i--) {
        uint8_t val = hex_char_to_byte(hex_str[i]);
        
        bigint->data[word_idx] |= ((uint32_t)val << bit_offset);
        
        bit_offset += 4;
        if (bit_offset >= 32) {
            bit_offset = 0;
            word_idx++;
        }
    }
}

// Convert BigInt to hex string - optimized
__device__ void bigint_to_hex(const BigInt* bigint, char* hex_str) {
    const char hex_chars[] = "0123456789abcdef";
    int idx = 0;
    bool leading_zero = true;
    
    // Process from most significant word to least
    #pragma unroll
    for (int i = 7; i >= 0; i--) {
        for (int j = 28; j >= 0; j -= 4) {
            uint8_t nibble = (bigint->data[i] >> j) & 0xF;
            if (nibble != 0 || !leading_zero || (i == 0 && j == 0)) {
                hex_str[idx++] = hex_chars[nibble];
                leading_zero = false;
            }
        }
    }
    
    // Handle case where number is 0
    if (idx == 0) {
        hex_str[idx++] = '0';
    }
    
    hex_str[idx] = '\0';
}

// Optimized byte to hex conversion
__device__ __forceinline__ void byte_to_hex(uint8_t byte, char* out) {
    const char hex_chars[] = "0123456789abcdef";
    out[0] = hex_chars[(byte >> 4) & 0xF];
    out[1] = hex_chars[byte & 0xF];
}

__device__ void hash160_to_hex(uint8_t* hash, char* hex_str) {
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        byte_to_hex(hash[i], &hex_str[i * 2]);
    }
    hex_str[40] = '\0';
}


__device__ __forceinline__ bool compare_hash160_fast(const uint8_t* hash1, const uint8_t* hash2) {
    uint64_t a1, a2, b1, b2;
    uint32_t c1, c2;
    
    memcpy(&a1, hash1, 8);
    memcpy(&a2, hash1 + 8, 8);
    memcpy(&c1, hash1 + 16, 4);

    memcpy(&b1, hash2, 8);
    memcpy(&b2, hash2 + 8, 8);
    memcpy(&c2, hash2 + 16, 4);

    return (a1 == b1) && (a2 == b2) && (c1 == c2);
}

__device__ void hash160_to_hex(const uint8_t *hash, char *out_hex) {
    const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 20; ++i) {
        out_hex[i * 2]     = hex_chars[hash[i] >> 4];
        out_hex[i * 2 + 1] = hex_chars[hash[i] & 0x0F];
    }
    out_hex[40] = '\0';
}
__device__ void generate_random_in_range(BigInt* result, curandStatePhilox4_32_10_t* state, 
                                         const BigInt* min_val, const BigInt* max_val) {
    
    BigInt range;
    
    bool borrow = false;
    
    for (int i = 0; i < BIGINT_WORDS; ++i) {
        uint64_t diff = (uint64_t)max_val->data[i] - (uint64_t)min_val->data[i] - (borrow ? 1 : 0);
        range.data[i] = (uint32_t)diff;
        borrow = (diff > 0xFFFFFFFFULL);
    }
    
    
    BigInt random;
    
    for (int w = 0; w < BIGINT_WORDS; w += 4) {
        uint4 r = curand4(state);
        if (w + 0 < BIGINT_WORDS) random.data[w + 0] = r.x;
        if (w + 1 < BIGINT_WORDS) random.data[w + 1] = r.y;
        if (w + 2 < BIGINT_WORDS) random.data[w + 2] = r.z;
        if (w + 3 < BIGINT_WORDS) random.data[w + 3] = r.w;
    }
    
    
    int highest_word = BIGINT_WORDS - 1;
    
    while (highest_word >= 0 && range.data[highest_word] == 0) {
        highest_word--;
    }
    
    if (highest_word >= 0) {
        
        uint32_t mask = range.data[highest_word];
        mask |= mask >> 1;
        mask |= mask >> 2;
        mask |= mask >> 4;
        mask |= mask >> 8;
        mask |= mask >> 16;
        
        
        asm volatile ("and.b32 %0, %1, %2;" 
                     : "=r"(random.data[highest_word]) 
                     : "r"(random.data[highest_word]), "r"(mask));
        
        
        
        for (int i = highest_word + 1; i < BIGINT_WORDS; ++i) {
            asm volatile ("mov.b32 %0, 0;" : "=r"(random.data[i]));
        }
        
        
        bool greater = false;
        
        for (int i = BIGINT_WORDS - 1; i >= 0; --i) {
            if (random.data[i] > range.data[i]) {
                greater = true;
                break;
            } else if (random.data[i] < range.data[i]) {
                break;
            }
        }
        
        
        if (greater) {
            
            for (int i = 0; i < BIGINT_WORDS; ++i) {
                uint32_t divisor = range.data[i] + 1;
                if (divisor != 0) {  
                    asm volatile ("rem.u32 %0, %1, %2;" 
                                 : "=r"(random.data[i]) 
                                 : "r"(random.data[i]), "r"(divisor));
                }
                
            }
        }
    }
    
    
    for (int i = 0; i < BIGINT_WORDS; ++i) {
        uint32_t r_word = random.data[i];
        uint32_t min_word = min_val->data[i];
        
        if (i == 0) {
            
            asm volatile ("add.cc.u32 %0, %1, %2;" 
                         : "=r"(result->data[0]) 
                         : "r"(r_word), "r"(min_word));
        } else if (i == BIGINT_WORDS - 1) {
            
            asm volatile ("addc.u32 %0, %1, %2;" 
                         : "=r"(result->data[i]) 
                         : "r"(r_word), "r"(min_word));
        } else {
            
            asm volatile ("addc.cc.u32 %0, %1, %2;" 
                         : "=r"(result->data[i]) 
                         : "r"(r_word), "r"(min_word));
        }
    }
}
__device__ __forceinline__ void hex_vertical_rotate_up(char* hex_str) {
    int actual_length = 0;
    #pragma unroll 8
    for (int i = 0; i < HEX_LENGTH; i++) {
        if (hex_str[i] == '\0') {
            actual_length = i;
            break;
        }
    }
    if (actual_length == 0) actual_length = HEX_LENGTH;
    
    if (actual_length <= 1) return;
    
    int first_one = -1;
    #pragma unroll 8
    for (int i = 0; i < actual_length; i++) {
        if (hex_str[i] == '1') {
            first_one = i;
            break;
        }
    }
    
    if (first_one == -1 || first_one >= actual_length - 1) return;
    
    // Increment all characters after the first '1' with manual unrolling
    int i = first_one + 1;
    int limit = actual_length;
    
    // Process 4 characters at a time
    for (; i + 3 < limit; i += 4) {
        hex_str[i] = hex_increment(hex_str[i]);
        hex_str[i + 1] = hex_increment(hex_str[i + 1]);
        hex_str[i + 2] = hex_increment(hex_str[i + 2]);
        hex_str[i + 3] = hex_increment(hex_str[i + 3]);
    }
    
    // Handle remaining characters
    for (; i < limit; i++) {
        hex_str[i] = hex_increment(hex_str[i]);
    }
}

__device__ __forceinline__ void invertHexAfterFirst1(char* hex) {
    // Find first '1'
    int first1_idx = -1;
    #pragma unroll 8
    for (int i = 0; i < 256 && hex[i] != '\0'; i++) {
        if (hex[i] == '1') {
            first1_idx = i;
            break;
        }
    }
    
    if (first1_idx == -1) return;
    
    // Invert all hex digits after first '1'
    int i = first1_idx + 1;
    
    // Process 4 characters at a time
    for (; hex[i] != '\0' && hex[i + 1] != '\0' && hex[i + 2] != '\0' && hex[i + 3] != '\0'; i += 4) {
        char c0 = hex[i];
        char c1 = hex[i + 1];
        char c2 = hex[i + 2];
        char c3 = hex[i + 3];
        
        // Fast inversion using XOR trick
        // For hex chars: '0'-'9' are 0x30-0x39, 'a'-'f' are 0x61-0x66
        // Invert the low 4 bits
        int v0 = hex_char_to_byte(c0);
        int v1 = hex_char_to_byte(c1);
        int v2 = hex_char_to_byte(c2);
        int v3 = hex_char_to_byte(c3);
        
        v0 = (~v0) & 0xF;
        v1 = (~v1) & 0xF;
        v2 = (~v2) & 0xF;
        v3 = (~v3) & 0xF;
        
        hex[i] = (v0 < 10) ? ('0' + v0) : ('a' + (v0 - 10));
        hex[i + 1] = (v1 < 10) ? ('0' + v1) : ('a' + (v1 - 10));
        hex[i + 2] = (v2 < 10) ? ('0' + v2) : ('a' + (v2 - 10));
        hex[i + 3] = (v3 < 10) ? ('0' + v3) : ('a' + (v3 - 10));
    }
    
    // Handle remaining characters
    for (; hex[i] != '\0'; i++) {
        char c = hex[i];
        int val = hex_char_to_byte(c);
        val = (~val) & 0xF;
        hex[i] = (val < 10) ? ('0' + val) : ('a' + (val - 10));
    }
}
__device__ __forceinline__ void reverseAfterFirst1(char* hex) {
    // Find first '1'
    char* first1 = hex;
    #pragma unroll 8
    while (*first1 && *first1 != '1') first1++;
    
    if (*first1 == '\0' || *(first1 + 1) == '\0') return;
    
    // Find end
    char* end = first1 + 1;
    #pragma unroll 8
    while (*end) end++;
    end--;
    
    // Reverse after '1' with manual unrolling
    char* start = first1 + 1;
    
    // Process 4 swaps at a time
    while (start + 3 < end - 3) {
        char temp0 = *start;
        char temp1 = *(start + 1);
        char temp2 = *(start + 2);
        char temp3 = *(start + 3);
        
        *start = *end;
        *(start + 1) = *(end - 1);
        *(start + 2) = *(end - 2);
        *(start + 3) = *(end - 3);
        
        *end = temp0;
        *(end - 1) = temp1;
        *(end - 2) = temp2;
        *(end - 3) = temp3;
        
        start += 4;
        end -= 4;
    }
    
    // Handle remaining swaps
    while (start < end) {
        char temp = *start;
        *start = *end;
        *end = temp;
        start++;
        end--;
    }
}

__device__ __forceinline__ void hex_rotate_left_by_one(char* hex_str) {
    int actual_length = 0;
    #pragma unroll 8
    for (int i = 0; i < 256; i++) {
        if (hex_str[i] == '\0') {
            actual_length = i;
            break;
        }
    }
    if (actual_length == 0) actual_length = 256;
    
    if (actual_length <= 1) return;
    
    // Find first non-'0' character
    int first_nonzero = -1;
    #pragma unroll 8
    for (int i = 0; i < actual_length; i++) {
        if (hex_str[i] != '0') {
            first_nonzero = i;
            break;
        }
    }
    
    if (first_nonzero == -1 || first_nonzero >= actual_length - 1) return;
    
    int rotation_start = first_nonzero + 1;
    int rotation_length = actual_length - rotation_start;
    
    if (rotation_length <= 1) return;
    
    char first_char = hex_str[rotation_start];
    
    // Optimized copy with manual unrolling
    int i = 0;
    int limit = rotation_length - 1;
    
    // Process 4 at a time manually
    for (; i + 3 < limit; i += 4) {
        hex_str[rotation_start + i] = hex_str[rotation_start + i + 1];
        hex_str[rotation_start + i + 1] = hex_str[rotation_start + i + 2];
        hex_str[rotation_start + i + 2] = hex_str[rotation_start + i + 3];
        hex_str[rotation_start + i + 3] = hex_str[rotation_start + i + 4];
    }
    
    // Remaining elements
    for (; i < limit; i++) {
        hex_str[rotation_start + i] = hex_str[rotation_start + i + 1];
    }
    
    hex_str[rotation_start + rotation_length - 1] = first_char;
}

// Global device constants for min/max as BigInt
__constant__ BigInt d_min_bigint;
__constant__ BigInt d_max_bigint;

__device__ volatile int g_found = 0;
__device__ char g_found_hex[65] = {0};
__device__ char g_found_hash160[41] = {0};

__device__ char d_min_hex[65];
__device__ char d_max_hex[65];
__device__ int d_hex_length;

__global__ void start(const uint8_t* target, uint64_t p1, int length)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    
    curandStatePhilox4_32_10_t state;
    curand_init(p1, tid, 0, &state);
    
    ECPointJac result_jac_batch[BATCH_SIZE];
    BigInt priv_batch[BATCH_SIZE];
    uint8_t hash160_batch[BATCH_SIZE][20];
    
    // Generate initial random keys
    #pragma unroll
    for (int i = 0; i < BATCH_SIZE; ++i) {
        generate_random_in_range(&priv_batch[i], &state, &d_min_bigint, &d_max_bigint);
    }
    int transforms = 2 * 2 * (length - 1) * 16;
    for(int inv = 0; inv < 2; inv++)
    {
		for(int z = 0; z < 2; z++)
		{
			for(int y = 0; y < length - 1; y++)
			{
				for(int x = 0; x < 16; x++)
				{
					for (int i = 0; i < BATCH_SIZE; ++i) {
						scalar_multiply_multi_base_jac(&result_jac_batch[i], &priv_batch[i]);
					}
					
					
					// Batch convert to hash160
					jacobian_batch_to_hash160(result_jac_batch, hash160_batch);
					
					for (int i = 0; i < BATCH_SIZE; ++i) {
						if (tid == 0 && i == 0 && inv == 0 && z == 0 && x == 0) {
							char hex_key[65];
							char hash160_str[41];
							
							bigint_to_hex(&priv_batch[i], hex_key);
							hash160_to_hex(hash160_batch[i], hash160_str);
							printf("Thread %d - Base Key: %s -> %s | Applying %d transformations on this base key(inverse, reverse, rotations(y/x))\n", tid, hex_key, hash160_str, transforms);
						}
					}
					

					for (int i = 0; i < BATCH_SIZE; ++i) {
						if (compare_hash160_fast(hash160_batch[i], target)) {
							if (atomicCAS((int*)&g_found, 0, 1) == 0) {
								bigint_to_hex(&priv_batch[i], g_found_hex);
								hash160_to_hex(hash160_batch[i], g_found_hash160);
							}
							return;
						}
					}
					
					for (int i = 0; i < BATCH_SIZE; ++i) {
						char hex_chunk[65];
						bigint_to_hex(&priv_batch[i], hex_chunk);
						hex_vertical_rotate_up(hex_chunk);
						hex_to_bigint(hex_chunk, &priv_batch[i]);
					}
				}
				for (int i = 0; i < BATCH_SIZE; ++i) {
					char hex_chunk[65];
					bigint_to_hex(&priv_batch[i], hex_chunk);
					hex_rotate_left_by_one(hex_chunk);
					hex_to_bigint(hex_chunk, &priv_batch[i]);
				}
			}
			for (int i = 0; i < BATCH_SIZE; ++i) {
				char hex_chunk[65];
				bigint_to_hex(&priv_batch[i], hex_chunk);
				reverseAfterFirst1(hex_chunk);
				hex_to_bigint(hex_chunk, &priv_batch[i]);
			}
		}
		for (int i = 0; i < BATCH_SIZE; ++i) {
			char hex_chunk[65];
			bigint_to_hex(&priv_batch[i], hex_chunk);
			invertHexAfterFirst1(hex_chunk);
			hex_to_bigint(hex_chunk, &priv_batch[i]);
		}
	}
}

bool run_with_quantum_data(const char* min, const char* max, const char* target, int blocks, int threads, int device_id) {
    uint8_t shared_target[20];
    hex_string_to_bytes(target, shared_target, 20);
    uint8_t *d_target;
    cudaMalloc(&d_target, 20);
    cudaMemcpy(d_target, shared_target, 20, cudaMemcpyHostToDevice);
    
    // Convert min and max hex strings to BigInt and copy to device
    BigInt min_bigint, max_bigint;
    hex_to_bigint(min, &min_bigint);
    hex_to_bigint(max, &max_bigint);
    
    cudaMemcpyToSymbol(d_min_bigint, &min_bigint, sizeof(BigInt));
    cudaMemcpyToSymbol(d_max_bigint, &max_bigint, sizeof(BigInt));
    
    int total_threads = blocks * threads;
    int found_flag;
    
    // Calculate keys processed per kernel launch
    uint64_t keys_per_kernel = (uint64_t)blocks * threads * BATCH_SIZE;
    
    printf("Searching in range:\n");
    printf("Min: %s\n", min);
    printf("Max: %s\n", max);
    printf("Target: %s\n", target);
    printf("Blocks: %d, Threads: %d, Batch size: %d\n", blocks, threads, BATCH_SIZE);
    printf("Total threads: %d\n", total_threads);
    printf("Keys per kernel: %llu\n\n", (unsigned long long)keys_per_kernel);
    
    uint64_t p1;
    // Performance tracking variables
    uint64_t total_keys_checked = 0;
    auto start_time = std::chrono::high_resolution_clock::now();
    //auto last_print_time = start_time;
    int length = strlen(min);
    while(true) {
		BCryptGenRandom(NULL, (PUCHAR)&p1, sizeof(p1), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        auto kernel_start = std::chrono::high_resolution_clock::now();
        
        // Launch kernel
        start<<<blocks, threads>>>(d_target, p1, length);
        cudaDeviceSynchronize();
        
        auto kernel_end = std::chrono::high_resolution_clock::now();
        
        // Calculate kernel execution time
        double kernel_time = std::chrono::duration<double>(kernel_end - kernel_start).count();
        
        // Update counters
        total_keys_checked += keys_per_kernel;
        
        
        // Check if key was found
        cudaMemcpyFromSymbol(&found_flag, g_found, sizeof(int));
        if (found_flag) {
            printf("\n\n");
            
            char found_hex[65], found_hash160[41];
            cudaMemcpyFromSymbol(found_hex, g_found_hex, 65);
            cudaMemcpyFromSymbol(found_hash160, g_found_hash160, 41);
            
            double total_time = std::chrono::duration<double>(
                std::chrono::high_resolution_clock::now() - start_time
            ).count();
            
            printf("FOUND!\n");
            printf("Private Key: %s\n", found_hex);
            printf("Hash160: %s\n", found_hash160);
            printf("Total time: %.2f seconds\n", total_time);
            printf("Total keys checked: %llu (%.2f billion)\n", 
                   (unsigned long long)total_keys_checked,
                   total_keys_checked / 1000000000.0);
            printf("Average speed: %.2f MK/s\n", total_keys_checked / total_time / 1000000.0);
            
            std::ofstream outfile("result.txt", std::ios::app);
            if (outfile.is_open()) {
                std::time_t now = std::time(nullptr);
                char timestamp[100];
                std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
                outfile << "[" << timestamp << "] Found: " << found_hex << " -> " << found_hash160 << std::endl;
                outfile << "Total keys checked: " << total_keys_checked << std::endl;
                outfile << "Time taken: " << total_time << " seconds" << std::endl;
                outfile << "Average speed: " << (total_keys_checked / total_time / 1000000.0) << " MK/s" << std::endl;
                outfile << std::endl;
                outfile.close();
                std::cout << "Result appended to result.txt" << std::endl;
            }
            
            cudaFree(d_target);
            return true;
        }
        
        // Update seed for next iteration
        //p1 += 1;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <min> <max> <target> [blocks] [threads] [device_id]" << std::endl;
        return 1;
    }
    
    int blocks = (argc >= 5) ? std::stoi(argv[4]) : 128;
    int threads = (argc >= 6) ? std::stoi(argv[5]) : 128;
    int device_id = (argc >= 7) ? std::stoi(argv[6]) : 0;
    
    init_gpu_constants();
    cudaDeviceSynchronize();
    
    bool result = run_with_quantum_data(argv[1], argv[2], argv[3], blocks, threads, device_id);
    
    return 0;
} 