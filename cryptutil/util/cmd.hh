#include <string>

char* get_cmd_option(char ** begin, size_t argc, const std::string & option);
bool cmd_option_exists(char **argv, size_t argc, const std::string &option);

#ifndef CMD_H
#define CMD_H

template <typename T>
bool cmd_one_exists(char **begin, size_t argc, T t) {
    return cmd_option_exists(begin, argc, t);
}

template <typename T, typename ...Args>
bool cmd_one_exists(char **begin, size_t argc, T t, Args ...args) {
    if(cmd_option_exists(begin, argc, t)) {
        return true;
    }

    return cmd_one_exists(begin, argc, args...);
}

template <typename ...Args>
bool cmd_one_exists(char **begin, size_t argc, Args ...args) {
    return cmd_one_exists(args...);
}

#endif