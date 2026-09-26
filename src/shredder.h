#pragma once
#include <string>

class Shredder {
public:
    enum Passes { Single = 1, Triple = 3, DOD = 7 };

    static bool shred(const std::wstring& filepath, int passes = Triple);
    static bool shredAndDelete(const std::wstring& filepath, int passes = Triple);
};
