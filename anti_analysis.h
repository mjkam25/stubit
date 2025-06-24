#ifndef ANTI_ANALYSIS_H
#define ANTI_ANALYSIS_H

#include <intrin.h>
#include <vector>
#include <random>
#include <stdexcept>
#include <chrono>
#pragma once
#include <windows.h>

void JunkCode();
bool IsDebugged();
bool IsInsideVM();
bool IsSandboxed();


// Fonction pour générer du code junk (obfuscation)
void JunkCode() {
    volatile int junk = 0;
    for (int i = 0; i < 10; ++i) {
        junk += i * rand();
    }
}

// Détection de debugger via IsDebuggerPresent
bool IsDebugged() {
    return IsDebuggerPresent() != 0;
}

// Détection de debugger via CheckRemoteDebuggerPresent
bool IsDebugged_Remote() {
    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
    return isDebugged != FALSE;
}

// Détection de VM via CPUID (Hypervisor Bit)
bool IsInsideVM() {
    unsigned int hypervisorBit;
    __asm__ __volatile__ (
        "mov $1, %%eax\n"
        "cpuid\n"
        "mov %%ecx, %0\n"
        : "=r" (hypervisorBit)
        :
        : "%eax", "%ebx", "%ecx", "%edx"
    );
    return (hypervisorBit & (1 << 31)) != 0;
}

// Détection de sandbox via le temps d'exécution (ex: < 2s = sandbox)
bool IsSandboxed() {
    auto start = std::chrono::high_resolution_clock::now();
    volatile int junk = 0;
    for (int i = 0; i < 1000000; ++i) {
        junk += i * rand();
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    return duration < 100; // Si < 100ms, probablement une sandbox
}

// Détection de breakpoints via lecture mémoire
bool HasBreakpoints() {
    unsigned char *ptr = (unsigned char *)IsDebugged;
    for (size_t i = 0; i < 100; ++i) {
        if (ptr[i] == 0xCC) { // 0xCC = INT3 (breakpoint)
            return true;
        }
    }
    return false;
}

bool VerifyStubIntegrity(); // Déclaration seulement



#endif // ANTI_ANALYSIS_H
