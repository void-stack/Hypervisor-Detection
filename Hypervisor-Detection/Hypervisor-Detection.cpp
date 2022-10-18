#include <intrin.h>
#include <iostream>
#include <Windows.h>
#include <format>
#include <functional>
#include <future>
#include <map>

const std::string ascii = R"(
	 _    _                             _                
	| |  | |                           (_)               
	| |__| |_   _ _ __   ___ _ ____   ___ ___  ___  _ __ 
	|  __  | | | | '_ \ / _ \ '__\ \ / / / __|/ _ \| '__|
	| |  | | |_| | |_) |  __/ |   \ V /| \__ \ (_) | |   
	|_|  |_|\__, | .__/ \___|_|    \_/ |_|___/\___/|_|   
	         __/ | |                                     
	 _____  |___/|_|          _   _                      
	|  __ \     | |          | | (_)                     
	| |  | | ___| |_ ___  ___| |_ _  ___  _ __           
	| |  | |/ _ \ __/ _ \/ __| __| |/ _ \| '_ \          
	| |__| |  __/ ||  __/ (__| |_| | (_) | | | |         
	|_____/ \___|\__\___|\___|\__|_|\___/|_| |_|

		  https://github.com/void-stack

)";

#ifdef _WIN64
extern "C" void __fastcall _asm_fyl2xp1(void);
#endif

struct _cpuid_buffer_t
{
	uint32_t EAX;
	uint32_t EBX;
	uint32_t ECX;
	uint32_t EDX;
};

// resources [check #Improvement Part https://secret.club/2020/01/12/battleye-hypervisor-detection.html] 
bool take_time()
{
	// If the CPUID instruction execution time is longer than the arithmetic
	// instruction it’s a reliable indication that the system is virtualized
	// because under no circumstances should the arithmetic instruction take
	// longer than the CPUID execution to grab vendor, or version information.
	// This detection will also catch those using TSC offsetting/scaling.

	constexpr auto measure_time = 5;

	long long __cpuid_time   = 0;
	long long __fyl2xp1_time = 0;

	LARGE_INTEGER frequency = {};
	LARGE_INTEGER start     = {};
	LARGE_INTEGER end       = {};

	QueryPerformanceFrequency(&frequency);

	// count the average time it takes to execute a CPUID instruction
	for (std::size_t i = 0; i < measure_time; ++i)
	{
		QueryPerformanceCounter(&start);
		_cpuid_buffer_t cpuid_data;
		__cpuid(reinterpret_cast<int*>(&cpuid_data), 1);
		QueryPerformanceCounter(&end);

		auto delta = end.QuadPart - start.QuadPart;

		delta *= 1000000000;
		delta /= frequency.QuadPart;

		__cpuid_time += delta;
	}

	// count the average time it takes to execute a FYL2XP1 instruction
	for (std::size_t i = 0; i < measure_time; ++i)
	{
		QueryPerformanceCounter(&start);
		#ifdef _WIN64
		_asm_fyl2xp1();
		#else
		_asm FYL2XP1
		#endif
		QueryPerformanceCounter(&end);

		auto delta = end.QuadPart - start.QuadPart;

		delta *= 1000000000;
		delta /= frequency.QuadPart;

		__fyl2xp1_time += delta;
	}

	return __fyl2xp1_time <= __cpuid_time;
}

// resources [check https://secret.club/2020/01/12/battleye-hypervisor-detection.html] #Improvement Part
bool take_time_cpuid_against_fyl2xp1()
{
	constexpr auto measure_times = 5;
	auto positives               = 0;
	auto negatives               = 0;

	// run the internal VM check multiple times to get an average result
	for (auto i = measure_times; i != 0; --i)
		take_time() ? ++positives : ++negatives;

	// if there are more positive results than negative results, the
	// process is likely running inside a VM
	const bool decision = (positives >= negatives);

	return decision;
}

// resources https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html
bool check_invalid_leaf()
{
	constexpr unsigned int invalid_leaf = 0x04201337;
	constexpr unsigned int valid_leaf   = 0x40000000;

	_cpuid_buffer_t InvalidLeafResponse = {};
	_cpuid_buffer_t ValidLeafResponse   = {};

	__cpuid(reinterpret_cast<int32_t*>(&InvalidLeafResponse), invalid_leaf);
	__cpuid(reinterpret_cast<int32_t*>(&ValidLeafResponse), valid_leaf);

	if ((InvalidLeafResponse.EAX != ValidLeafResponse.EAX) ||
		(InvalidLeafResponse.EBX != ValidLeafResponse.EBX) ||
		(InvalidLeafResponse.ECX != ValidLeafResponse.ECX) ||
		(InvalidLeafResponse.EDX != ValidLeafResponse.EDX))
		return true;

	return false;
}

// resources https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html
bool check_highest_low_function_leaf()
{
	constexpr auto queryVendorIdMagic = 0x40000000;

	_cpuid_buffer_t regs = {};
	__cpuid(reinterpret_cast<int32_t*>(&regs), queryVendorIdMagic);

	_cpuid_buffer_t reserved_regs = {};
	__cpuid(reinterpret_cast<int32_t*>(&reserved_regs), 1);

	__cpuid(reinterpret_cast<int32_t*>(&reserved_regs), reserved_regs.EAX);

	if (reserved_regs.EAX != regs.EAX ||
		reserved_regs.EBX != regs.EBX ||
		reserved_regs.ECX != regs.ECX ||
		reserved_regs.EDX != regs.EDX)
		return true;

	return false;
}

// resouces https://kb.vmware.com/s/article/1009458
bool check_for_known_hypervisor()
{
	_cpuid_buffer_t cpuInfo = {};
	__cpuid(reinterpret_cast<int32_t*>(&cpuInfo), 1);

	if (!(cpuInfo.ECX & (1 << 31))) // check bit 31 of register ECX, which is “hypervisor present bit”
		return false;               // if not present return

	// we know hypervisor is present we can query the vendor id.
	constexpr auto queryVendorIdMagic = 0x40000000;
	__cpuid(reinterpret_cast<int32_t*>(&cpuInfo), queryVendorIdMagic);

	// construct string for our vendor name
	constexpr auto size      = 13;
	const auto presentVendor = new char[size];
	memcpy(presentVendor + 0, &cpuInfo.EBX, 4);
	memcpy(presentVendor + 4, &cpuInfo.ECX, 4);
	memcpy(presentVendor + 8, &cpuInfo.EDX, 4);
	presentVendor[12] = '\0';

	// check against known vendor names
	const char* vendors[]{
		"KVMKVMKVM\0\0\0", // KVM 
		"Microsoft Hv",    // Microsoft Hyper-V or Windows Virtual PC */
		"VMwareVMware",    // VMware 
		"XenVMMXenVMM",    // Xen 
		"prl hyperv  ",    // Parallels
		"VBoxVBoxVBox"     // VirtualBox 
	};

	for (const auto& vendor : vendors)
	{
		if (!memcmp(vendor, presentVendor, size))
		{
			std::cout << "\tFound known hypervisor: " << presentVendor << std::endl;
			return true;
		}
	}

	std::cout << "\tFound unknown hypervisor: " << presentVendor << std::endl;
	return false;
}

void arch()
{
	if constexpr (const int* pInt = nullptr; sizeof(pInt) == 8)
		std::cout << "Version: x64" << std::endl;
	else if constexpr (sizeof(pInt) == 4)
		std::cout << "Version: x86" << std::endl;
}

int main()
{
	// test all functions
	const std::map<std::string_view, std::function<bool()>> callbacks = {
		{"Profiling CPUID against FYL2XP1", &take_time_cpuid_against_fyl2xp1},
		{"Checking highest low function leaf", &check_highest_low_function_leaf},
		{"Checking invalid leaf", &check_invalid_leaf},
		{"Checking for known hypervisor vendors", &check_for_known_hypervisor}
	};

	std::cout << ascii << std::endl;

	arch();

	const auto log = [&](const std::function<bool()> callback,
						 const std::string_view label)
	{
		const std::uint32_t condition = callback();

		(condition
			 ? std::cout
			 << "* [" << label << "] ~ " << "Detected [!]"
			 : std::cout
			 << "* " << label << " ~ " << "Passed [+]") << std::endl;
	};

	for (const auto& [callback, value] : callbacks)
		log(value, callback);

	std::cin.get();
}
