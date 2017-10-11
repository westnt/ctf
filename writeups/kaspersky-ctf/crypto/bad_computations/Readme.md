### Challange prompt
The creators of a certain system have taken care of the security of storing users data and encrypted users passwords. To register a new user the administrator should enter encrypted password into the database. You were able to get a users passwords database and a script, that administrator used for passwords encryption. The answer for this task is the password the encrypted version of which: hnd/goJ/e4h1foWDhYOFiIZ+f3l1e4R5iI+Gin+FhA==
### Solution
We are given the encrypted string "hnd/goJ/e4h1foWDhYOFiIZ+f3l1e4R5iI+Gin+FhA==" and the algorithm used to create the string "crypt.py".

Looking at crypt.py we find it looks a lot like RSA (its not as we will find out).
```py
    p = choice(dwfregrgre(100, 1000))
    q = choice(dwfregrgre(200, 1000))
    n = p*q
```
The function dwfregrgre creates an array of primes between 100 and 1000.
So p and q are chosen to be two primes.
Then n is calculated.

So far so RSA.

```py
    g = None
    for i in range(n + 1, n * n):
        if ((i % p) == 0) or ((i % q) == 0) or ((i % n) == 0):
            continue

        g = i
        break
```
Then value g is chosen to be non divisable to p,q, and n.

```py
    lamb = (p - 1) * (q - 1)
    mu = swsdwdwdwa(L(pow(g, lamb, n * n), n), n) % n
    rc = sdsd(n-1)
```
Then we have lamb and some calculated value mu. It doesnt matter much to the algorithm what mu is
so I wont discuss what the function swsdwdwdwa does.

```py
rc = sdsd(n - 1)
    if len(rc) == 0:
        print("Error! Candidates for r not found!")
        exit()

    if p in rc:
        rc.remove(p)
    if q in rc:
        rc.remove(q)

    r = choice(rc)
```

Our first issue comes up with function sdsd(). The function takes much to long to compute so
we will look into optimizing it. Without getting into the details, sdsd returns an array of numbers which
is assigned to rc. Then r = choice(rc) so r is a random value from rc.
That means any value of rc should work for a value of r so sdsn doesnt need to generate all those numbers
for the encryption to work.


Lets modify the range in sdsd to select values from range(edefefef-100, edefefef) to give us a performance boost.
```py
def sdsd(edefefef):
    fvfegve = [x for x in range(edefefef-100, edefefef)]

    x = 2
    rrerrrr = True
    while rrerrrr:
        for i in range(x * x, edefefef, x):
            if i in fvfegve:
                fvfegve.remove(i)

        rrerrrr = False
        for i in fvfegve:
            if i > x:
                x = i
                rrerrrr = True
                break

    return fvfegve
```

Now the algorithm runs in resonable time.

Lets look at the rest of the algorithm:
```py
wdwfewgwggrgrg = [ord(x) for x in argv[1][6:-1]]
    dcew = (pow(g, b, (n * n)) * pow(r, n, (n * n))) % (n * n)

    for i in range(len(wdwfewgwggrgrg)):
        wdwfewgwggrgrg[i] = (((pow(g, wdwfewgwggrgrg[i], (n * n)) * pow(r, n, (n * n))) % (n * n)) * dcew) % (n * n)
        wdwfewgwggrgrg[i] = (L(pow(wdwfewgwggrgrg[i], lamb, (n * n)), n) * mu) % n

    wdwfewgwggrgrg = b64encode(bytearray(wdwfewgwggrgrg))
    print(str(wdwfewgwggrgrg)[2:-1])
```

wdwfewgwggrgrg is the user input array. The message is encrypted in the for loop and then encoded into base64 before being printed out.

Lets print out the contents of the array before and after the for loop.
```py
    print(wdwfewgwggrgrg)
    for i in range(len(wdwfewgwggrgrg)):
        wdwfewgwggrgrg[i] = (((pow(g, wdwfewgwggrgrg[i], (n * n)) * pow(r, n, (n * n))) % (n * n)) * dcew) % (n * n)
        wdwfewgwggrgrg[i] = (L(pow(wdwfewgwggrgrg[i], lamb, (n * n)), n) * mu) % n
    print(wdwfewgwggrgrg)
```

Sample output
```
$ python3 crypt.py KLCTF{wow_a_message}
Key cryptor v1.0
Waiting for encryption...
[119, 111, 119, 95, 97, 95, 109, 101, 115, 115, 97, 103, 101]
[141, 133, 141, 117, 119, 117, 131, 123, 137, 137, 119, 125, 123]
jYWNdXd1g3uJiXd9ew==
```

It turns out the end result of the encryption process is simply adding 22 to the input. ^_^

Decoding our message is easy
```py
    msg = bytearray(b64decode("hnd/goJ/e4h1foWDhYOFiIZ+f3l1e4R5iI+Gin+FhA=="))
    for i in range(len(msg)):
        msg[i] = msg[i] - 22
    print(msg.decode("utf-8"))
```

output: paillier_homomorphic_encryption

