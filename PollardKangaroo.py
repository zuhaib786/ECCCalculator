import Numbthy as Calc
import random
def makeMap(n:int)->"map[int]":
    '''
    @param n: Field base modulo
    Outputs: A pseudo random function(map) from Z_n to Z_2n
    '''
    dic = {}
    for i in range(n):
        dic[i] = random.randint(0,2*n)
    return dic
def pollardKang(n : int, g : int, a : int, failedTimes : int)->"tuple[int]":
    '''
    @param n: Field base modulo
    @param g: Generator of the cyclic group under consideration
    @param a: The number whose dlog is to be calculated
    @param failedTimes: A threshold for number of failures
    Outputs: Tuple (d, dj) which satisfied g^d = ag^dj
    '''
    if failedTimes > 100000:
        print('[-] Something wrong')
        return (-1, -1)
    Di = makeMap(n)
    N = random.randint(5, 100)
    b = n - 1
    x_0 = Calc.power_mod(g, b, n)
    d = 0
    # dxVal = []
    # xj = []
    # xj.append(x_0)
    # dxVal.append(b)
    for i in range(N):
        x_1 = Di[x_0]
        d += x_1
        x_0 = (x_0*Calc.power_mod(g,x_1, n))%n
    y_0 = a
    dVal = []
    newDVal = 0
    for i in range(N):
        y_1 = Di[y_0]
        dVal.append(newDVal + y_1)
        newDVal += y_1
        y_0 = (y_0 * Calc.power_mod(g, y_1, n))%n
        if y_0 == x_0: 
            return (d, newDVal)
        elif newDVal > b + d:
            failedTimes += 1
            return pollardKang(n,g,a,failedTimes)
    return pollardKang(n,g,a,failedTimes + 1)
def Solve(g:int, a:int ,n:int )->int:
    '''
    @param g: The generator of the group
    @param a: The number whose dlog has to be calculated
    @param n: The base field
    Outputs: The value of dlog_g (a)
    '''
    failedTimes = 0
    d, dj =  pollardKang(n,g,a,failedTimes)
    phi = Calc.euler_phi(n)
    primes = Calc.factor(phi)
    for prime in primes:
        for _ in range(prime[1]):
            if(Calc.power_mod(g, phi//prime[0], n) == 1):
                phi = phi//prime[0]
            else:
                break
    return ((d- dj) % phi)
print(Solve(5,18,23))
print(Solve(7,214,337))

