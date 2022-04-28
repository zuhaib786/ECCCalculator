from multiprocessing.sharedctypes import Value
import Numbthy as Calc
class Point:
    def __init__(self, x:int, y:int):
        self.x = x
        self.y = y
    def __str__(self):
        return "Point "+str(self.x) + " "+ str(self.y)
        
class ECCurve:
    def gcdPrint(self,a, b):
        print(a, " = ", a//b , " $\\times$ ", b , " + ", a%b )
        if(a%b == 0):
            return
        self.gcdPrint(b, a % b)
    def __init__(self,a, b, n):
        self.a = a%n
        self.b = b%n
        self.n = n
        if(Calc.gcd(4*(self.a**3) + 27*(self.b**2) , n)!=1):
            print(Calc.gcd(4*(self.a**3) + 27*(self.b**2) , n)!=1)
    def satisfies(self,p):
        x = p.x
        y = p.y
        val = x**3 + self.a*(x) + self.b
        val %= self.n
        val -= y**2
        val %=self.n
        val+= self.n
        val %= self.n
        return val == 0
    def multiply(self, n, p):
        '''Calculates nP
        '''
        if n == 1:
            return p
        assert(n>1)
        curPoint = Point(p.x , p.y)
        for i in range(n-1):
            curPoint = self.add(curPoint, p)
        return curPoint
    def add(self, p1, p2):
        if p1.x == p2.x:
            if p1.y != p2.y:
                print("INFINITE")
                raise ValueError("Infinite aagya bro")
            else:
                slopeNum = 3*(p1.x**2) + self.a
                slopeNum %= self.n
                slopeDen = Calc.inverse_mod(2*p1.y, self.n)
                slope = slopeNum * slopeDen
                slope %= self.n
                x3 = slope**2 - 2*p1.x
                x3 %= self.n
                y3 = slope*(p1.x - x3) - p1.y
                y3 %= self.n
                x3 = (x3 + self.n)%self.n
                y3 = (y3 + self.n) % self.n
                return Point(x3, y3)
        else:
            slopeNum = p2.y - p1.y
            slopeDen = p2.x - p1.x
            slopeDen = Calc.inverse_mod(slopeDen , self.n)
            slopeNum = (slopeNum + self.n)%self.n
            sleopDen = (slopeDen + self.n)%self.n
            slope = (slopeNum * slopeDen)%self.n
            x3 = slope**2 - p1.x - p2.x
            x3%= self.n
            x3 = (x3 + self.n) % self.n
            y3 = slope*(p1.x - x3) - p1.y
            y3 %=self.n
            y3 += self.n
            y3 %= self.n
            return Point(x3, y3)
Ec = ECCurve(1,361,53467)
Ec.gcdPrint(105410, 53467)