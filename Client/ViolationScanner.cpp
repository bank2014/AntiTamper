#include "pch.h"
#include "ViolationScanner.h"

namespace ViolationScanner
{
	namespace
	{
		struct ViolationDetector
		{
			bool (*Probe)();
			Violation (*BuildViolation)();
		};

		const ViolationDetector kDetectors[] = {
			{ IsPeFileTampered, Violation::PeFileTampered },
			{ IsBlacklistedProgramPresent, Violation::BlacklistedProcess },
			{ IsDebugging, Violation::DebuggerAttached },
			{ IsSecureBootDisabled, Violation::SecureBootDisabled },
			{ IsAntivirusDisabled, Violation::AntivirusDisabled },
			{ IsHypervisorPresent, Violation::HypervisorDetected },
		};
	}

	std::vector<Violation> CollectCurrentViolations()
	{
		std::vector<Violation> violations;
		for (const ViolationDetector& detector : kDetectors)
		{
			if (detector.Probe())
				violations.push_back(detector.BuildViolation());
		}
		return violations;
	}
}
