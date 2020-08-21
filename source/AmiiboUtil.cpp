#include "AmiiboUtil.h"
#include "amiibo_map.h"
#include <fstream>

std::string AmiiboUtil::GetNameForID(uint64_t id)
{
    return amiibo_map[id];
};