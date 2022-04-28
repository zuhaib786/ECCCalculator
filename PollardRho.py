'''
    This code is part of the assignment given in the course MTL730-Cryptography in IIT Delhi, with prof. Rajendra Kumar Sharma as Instructor.
    In this code, we will implement pollards rho algorithm in python.
    To run this code it download Numbthyfile in the working directory(github link: https://github.com/Robert-Campbell-256/Number-Theory-Python/blob/master/numbthy.py)
'''
import Numbthy as Calc
import random
'''
We form 3 groups as G1 , G2 , G3 such that 
G1: x%3 = 0
G2: x%3 = 1
G3: x%3 = 2 
'''
def Add(tup1:"tuple[int]" , tup2:"tuple[int]")->"tuple[int]":
    if tup2[1] == -1:
        return (2 * tup1[0], 2 * tup1[1])
    else:
        return (tup1[0] + tup2[1], tup1[1] + tup2[2])
def func_f(b:int, n:int, g:int, a:int)->int:
    if b%3 == 0:
        return ((g*b)%n, 0, 1)
    elif b%3 == 1:
        return (Calc.power_mod(b, 2, n), -1, -1)
    else:
        return ((a*b)%n, 1, 0)
def PollardRho(g:int, a:int, n:int)->int:
    '''
    g: Generator
    a: g^dlog = a
    n: Base field modulo
    '''
    #initialize
    x_0 = random.randint(1, n)
    tup1 = (1 , x_0)
    b = Calc.power_mod(g, x_0, n)*a
    Di = {}
    Di[b] = tup1 
    while True:
        x = func_f(b,n, g, a)
        tup1 = Add(tup1, x)
        b = x[0]
        if b in Di.keys():
            break
        else:
            Di[b] = tup1
    x_0, y_0 = Di[b]
    x_1, y_1 = tup1
    # print(Di[b], tup1,b)
    '''
    y_1 - y_0 = d(x_1 - x_0) mod (phi(n))
    '''
    phi = Calc.euler_phi(n)
    primes = Calc.factor(phi)
    for prime in primes:
        for _ in range(prime[1]):
            if(Calc.power_mod(g, phi//prime[0], n) == 1):
                phi = phi//prime[0]
            else:
                break
    val = Calc.gcd(x_1 - x_0, phi)
    if val == 1:
        v_inv = Calc.inverse_mod(phi +x_0 - x_1, phi)
        # print(v_inv)
        return ((y_1 - y_0)*(v_inv))%phi 
    else:
        if (y_1 - y_0) % val != 0:
            print('[-] Something wrong1')
            return - 1
        v_inv = Calc.inverse_mod((-x_1 + x_0)//val, phi//val)
        ans = (((y_1 - y_0)//val)*(v_inv))%(phi//val)
        for i in range(val):
            if Calc.power_mod(g, ans + i*(phi//val), n) == a:
                return ans + i*(phi//val)
        print('[-] Something wrong2')
        return -1
print(PollardRho(5, 18,23))
print(PollardRho(7, 214,337))
