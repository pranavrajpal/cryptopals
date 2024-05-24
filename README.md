# Cryptopals Solutions

These are my solutions to the [Cryptopals] challenges.

Currently, all of sets 1 through 6 are finished with the exception of challenges 31 and 32, and I am working on set 7 right now. I plan to eventually finish all 8 sets.

## Issues

If you find any problems, please open an issue and I will make changes as soon as I can. 

## Running

To run any of the solutions, find the location of the solution for that specific challenge and then, from the root of the repo, run:

    pdm run python -m <module path to solution>

For example, running challenge 52 could be done using `pdm run python -m cryptopals.set7.challenge52`. All of the solutions are placed into folders based on which set they are in, and are usually in their own python script named after the challenge number.

[Cryptopals]: https://cryptopals.com
