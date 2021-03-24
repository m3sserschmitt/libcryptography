#include "cmd.hh"

#include <algorithm>

char *get_cmd_option(char **begin, size_t argc, const std::string &option)
{
    char **itr = std::find(begin, begin + argc, option);
    if (itr != begin + argc && ++itr != begin + argc)
    {
        return *itr;
    }

    return 0;
}

bool cmd_option_exists(char **argv, size_t argc, const std::string &option)
{
    return std::find(argv, argv + argc, option) != argv + argc;
}