#include "../general.h"

void console::Base(Color color, const char* prefix, const char* text, va_list args)
{
	ProtectUltra();
	time_t currentTime;
	time(&currentTime);
	struct tm* timeInfo = localtime(&currentTime);
	char buffer[11];
	strftime(buffer, 9, E("%H:%M:%S"), timeInfo);

	HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);

	SetConsoleTextAttribute(consoleHandle, static_cast<WORD>(Color::White));
	printf(E("[%s]"), buffer);

	SetConsoleTextAttribute(consoleHandle, static_cast<WORD>(color));
	printf(E("[%s] "), prefix);

	SetConsoleTextAttribute(consoleHandle, static_cast<WORD>(Color::DarkWhite));
	vprintf(text, args);
	printf(E("\n"));
	ProtectEnd();
}

void console::Info(const char* text, ...)
{
	ProtectUltra();
	va_list args;
	va_start(args, text);
	Base(Color::Cyan, E("i"), text, args);
	va_end(args);
	ProtectEnd();
}

void console::Warning(const char* text, ...)
{
	ProtectUltra();
	va_list args;
	va_start(args, text);
	Base(Color::Yellow, E("w"), text, args);
	va_end(args);
	ProtectEnd();
}

void console::Error(const char* text, ...)
{
	ProtectUltra();
	va_list args;
	va_start(args, text);
	Base(Color::Red, E("e"), text, args);
	va_end(args);
	ProtectEnd();
}

void console::Success(const char* text, ...)
{
	ProtectUltra();
	va_list args;
	va_start(args, text);
	Base(Color::Green, E("s"), text, args);
	va_end(args);
	ProtectEnd();
}

void console::Debug(const char* text, ...)
{
	ProtectUltra();
	va_list args;
	va_start(args, text);
	Base(Color::DarkGrey, E("d"), text, args);
	va_end(args);
	ProtectEnd();
}

void console::Clear()
{
	system(E("cls"));
}

void console::Init()
{
	ProtectUltra();
	CONSOLE_FONT_INFOEX cfi;
	cfi.cbSize = sizeof cfi;
	cfi.nFont = 0;
	cfi.dwFontSize.X = 0;
	cfi.dwFontSize.Y = 12;
	cfi.FontFamily = FF_DONTCARE;
	cfi.FontWeight = FW_NORMAL;
	wcscpy(cfi.FaceName, E(L"Lucida Console"));

	HANDLE console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
	SetCurrentConsoleFontEx(console_handle, FALSE, &cfi);

	HWND console_window = GetConsoleWindow();
	RECT r;
	GetWindowRect(console_window, &r);
	MoveWindow(console_window, r.left, r.top, 600, 600, TRUE);

	SetConsoleTitleA(E(" "));
	ProtectEnd();
}

void console::Title()
{
	ProtectUltra();
	HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);

	SetConsoleTextAttribute(consoleHandle, static_cast<WORD>(Color::Purple));
	printf(E("RwxMeme\n"));

	SetConsoleTextAttribute(consoleHandle, static_cast<WORD>(Color::DarkWhite));
	printf(E("build on %s | tulach.cc | github.com/SamuelTulach\n\n"), __DATE__);
	ProtectEnd();
}

void console::OverwriteClear()
{
	ProtectMutate();
	for (int i = 0; i < 10000; i++)
		printf(E("                                                                \n"));
	ProtectEnd();
}