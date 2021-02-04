from challenge5 import MersenneTwister
import random
import time


def crack_mt19937_seed_timestamp(rng, rand_num, current_time):
    """Cracks the MT19937 seed given the first output of the RNG
    and the current time if the RNG was seeded with the current time"""
    seed_guess = current_time
    while True:
        rng.seed_mt(seed_guess)
        calculated_num = rng.extract_number()
        if calculated_num == rand_num:
            return seed_guess
        seed_guess -= 1
        # break out of loop if taking too long
        if current_time - seed_guess >= 10000:
            break


def get_unix_timestamp():
    return int(time.time())


def challenge6():
    rng = MersenneTwister()
    timestamp = get_unix_timestamp()
    time_passing1 = random.randint(40, 1000)
    print(f'Actual seed: {timestamp + time_passing1}')
    rng.seed_mt(timestamp + time_passing1)
    time_passing2 = random.randint(40, 1000)
    num = rng.extract_number()
    seed = crack_mt19937_seed_timestamp(
        rng, num, timestamp + time_passing1 + time_passing2)
    print(f'Recovered seed: {seed}')


if __name__ == "__main__":
    challenge6()
