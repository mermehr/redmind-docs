# snowstorm.py - Texted based snowstorm animation

import os, random, time, sys
from inspect import FullArgSpec

TOP     = chr(9600) # Character 9600 is '▀'
BOTTOM  = chr(9604) # Charactor 9604 is '▄'
FULL    = chr(9608) # Charactor 9608 is '█'

# Set the snowstorm density in the command line argument
DENSITY = 4 # Default snow density is 4%
if len(sys.argv) > 1:
    DENSITY = int(sys.argv[-1])
    
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

while True:
    clear()
    
    # Loop over each row and column
    for y in range(20):
        for x in range(40):
            if random.randint(0, 99) < DENSITY:
                # Print snow
                print(random.choice([TOP, BOTTOM]), end='')
            else:
                # Print empty space:
                print(' ', end='')
        print()
        
    # Print the snow covered ground
    print(FULL * 40 + '\n' + FULL * 40)
    print('(Ctrl-C to stop)')
    
    time.sleep(0.2)
