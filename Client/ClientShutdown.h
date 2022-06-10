#pragma once

namespace AntiTamperShutdown
{
	bool RequestHostShutdown(const wchar_t* message, int fallbackExitCode);
}
