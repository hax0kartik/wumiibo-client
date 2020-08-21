#pragma once
#include <string>
#include <cinttypes>
#include "HTTPRequest.hpp"
class AmiiboUtil
{
    public:
        std::string GetNameForID(uint64_t id);
};