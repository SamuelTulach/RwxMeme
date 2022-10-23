#ifndef CONSOLE_H
#define CONSOLE_H

namespace console
{
	enum class Color
	{
		Default,
		DarkBlue,
		DarkGreen,
		DarkCyan,
		DarkRed,
		DarkPurple,
		DarkYellow,
		DarkWhite,
		DarkGrey,
		Blue,
		Green,
		Cyan,
		Red,
		Purple,
		Yellow,
		White
	};

	void Base(Color color, const char* prefix, const char* text, va_list args);
	void Info(const char* text, ...);
	void Warning(const char* text, ...);
	void Error(const char* text, ...);
	void Success(const char* text, ...);
	void Debug(const char* text, ...);
	void Clear();
	void Init();
	void Title();
	void OverwriteClear();
	std::string ReadInput(const char* text);
}

#endif