#pragma once

enum class ViolationSeverity
{
	Trivial = 0,
	Moderate = 1,
	Severe = 2
};

class Violation
{
public:
	constexpr Violation(ViolationSeverity severity, const char* reason)
		: _severity(severity), _reason(reason)
	{
	}

	constexpr ViolationSeverity Severity() const
	{
		return _severity;
	}

	constexpr int SeverityCode() const
	{
		return static_cast<int>(_severity);
	}

	constexpr const char* Reason() const
	{
		return _reason != nullptr ? _reason : "Unknown";
	}

	const char* SeverityName() const
	{
		switch (_severity)
		{
		case ViolationSeverity::Trivial:
			return "Trivial";
		case ViolationSeverity::Moderate:
			return "Moderate";
		case ViolationSeverity::Severe:
			return "Severe";
		default:
			return "Unknown";
		}
	}

	static constexpr Violation PeFileTampered()
	{
		return Violation(ViolationSeverity::Severe, "PeFileTampered");
	}

	static constexpr Violation BlacklistedProcess()
	{
		return Violation(ViolationSeverity::Trivial, "BlacklistedProcess");
	}

	static constexpr Violation DebuggerAttached()
	{
		return Violation(ViolationSeverity::Trivial, "DebuggerAttached");
	}

	static constexpr Violation SecureBootDisabled()
	{
		return Violation(ViolationSeverity::Moderate, "SecureBootDisabled");
	}

	static constexpr Violation AntivirusDisabled()
	{
		return Violation(ViolationSeverity::Moderate, "AntivirusDisabled");
	}

	static constexpr Violation HypervisorDetected()
	{
		return Violation(ViolationSeverity::Severe, "HypervisorDetected");
	}

private:
	ViolationSeverity _severity;
	const char* _reason;
};
