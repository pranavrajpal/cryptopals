from collections import namedtuple

MersenneTwisterConstants = namedtuple(
    "MersenneTwisterConstants", "w n m r a u d s b t c l f"
)

constants = MersenneTwisterConstants(
    w=32,
    n=624,
    m=397,
    r=31,
    a=0x9908B0DF,
    u=11,
    d=0xFFFFFFFF,
    s=7,
    b=0x9D2C5680,
    t=15,
    c=0xEFC60000,
    l=18,
    f=1812433253,
)


class MersenneTwister:
    def __init__(self, state=None):
        global constants
        self.constants = constants
        if state is None:
            self.state = [0] * constants.n
            self.index = None
        else:
            self.state = state
            self.index = constants.n
        self.lower_mask = (1 << constants.r) - 1
        self.upper_mask = self.lowest_w_bits(~self.lower_mask)

    def lowest_w_bits(self, num):
        # anding gives lowest w bits
        return num & ((1 << self.constants.w) - 1)

    def seed_mt(self, seed):
        constants = self.constants
        self.index = constants.n
        self.state[0] = seed
        # i goes from 1 to n-1
        for i in range(1, constants.n):
            prev_state = self.state[i - 1]
            state_value = (
                constants.f * (prev_state ^ (prev_state >> (constants.w - 2))) + i
            )
            self.state[i] = self.lowest_w_bits(state_value)

    def extract_number(self):
        constants = self.constants
        if self.index == None:
            raise ValueError("Generator was never seeded")
        elif self.index == constants.n:
            # generate next state and then get number from that
            self.twist()
        y = self.state[self.index]
        y ^= (y >> constants.u) & constants.d
        y ^= (y << constants.s) & constants.b
        y ^= (y << constants.t) & constants.c
        y ^= y >> constants.l
        self.index += 1
        return self.lowest_w_bits(y)

    def twist(self):
        constants = self.constants
        # i goes from 0 to n - 1
        for i in range(constants.n):
            x = (self.state[i] & self.upper_mask) + (
                self.state[(i + 1) % constants.n] & self.lower_mask
            )
            xA = x >> 1
            if x % 2 != 0:
                xA ^= constants.a
            before_xoring = self.state[(i + constants.m) % constants.n]
            self.state[i] = before_xoring ^ xA
        self.index = 0


def challenge5():
    # test the mersenne twister implementation
    twister = MersenneTwister()
    twister.seed_mt(42)
    for i in range(1000000):
        print(twister.extract_number())


if __name__ == "__main__":
    challenge5()
