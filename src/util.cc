#include <vector>
#include <string>

using namespace std;

vector<string> split(string str, string sep, int max_split)
{
    vector<string> tokens;
    
    size_t sep_pos;
    int split_index = 0;
    
    if (!str.size())
        return tokens;

    tokens.reserve(10);

    do
    {
        split_index++;
        sep_pos = str.find(sep);
        
        // tokens.resize(tokens.size() + 1);
        tokens.push_back(str.substr(0, sep_pos));
        if (sep_pos == string::npos) {
            // tokens.resize(split_index);
            return tokens;
        }
            
        str = str.substr(sep_pos + sep.size());
        if (split_index == max_split && str.size())
        {
            
            // tokens.resize(tokens.size() + 1);
            tokens.push_back(str);
            // tokens.resize(split_index + 1);
            return tokens;
        }
    } while (true);

    return tokens;
}