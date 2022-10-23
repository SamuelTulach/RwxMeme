#ifndef SERVICE_H
#define SERVICE_H

namespace service
{
	bool RegisterAndStart(const std::wstring& driver_path);
	bool StopAndRemove(const std::wstring& driver_name);
};

#endif