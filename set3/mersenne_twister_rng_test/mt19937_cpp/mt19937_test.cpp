#include <cstdio>
#include <cstdint>

#include <random>

int main()
{

    std::mt19937 rng(42);
    for (int i = 0; i < 1000000; i++)
    {
        uint32_t value = rng();
        printf("%u\n", value);
    }
}