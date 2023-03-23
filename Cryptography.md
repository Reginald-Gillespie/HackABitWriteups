<p style="text-align: center; font-size: 40px;"><strong>Hack A Bit: Cryptography</strong></p>

---
---
<br/><br/><br/><br/>
# 6532S, Homerun

Problem:
```
MZWGCZ33I5XXI5DBJVQWWZKTOVZGKWLPOVEGKYLSIFRG65LUKRUGC5CMN5XGOQTBNRWH2===
```
This looks like base64, but all the letters are capitalized. You can either google for a bit and find that it's base32, or just recognize it from experience.

A useful site throughout the cryptography section is [CyberChef](https://cyberchef.org/). Search for `From Base32` and drag that into the recipe section.

<details>
<summary>Solution</summary>

```
flag{GottaMakeSureYouHearAboutThatLongBall}
```
</details>

<br/><br/><br/><br/>
# SR300, Mason

Problem:
```
66 6c 61 67 7b 63 6f 6d 70 75 74 65 72 3a 69 5f 6f 6e 6c 79 5f 75 6e 64 65 72 73 74 61 6e 64 5f 62 69 6e 61 72 79 5f 64 75 64 65 7d
```
Just like last time, you can google some of the more distinct characters, or just recognize it as being hex encoding. CyberChef has a `From Hex` module that will decode it.
<details>
<summary>Solution</summary>

```
flag{computer:i_only_understand_binary_dude}
```
</details>


<br/><br/><br/><br/>
# 08ZLE, Smiley

Problem:
```
🤣😅😇😉 😁😅😀🥰🤣 😚🥰😜🤗😇🤑🤫😉 😀 🫡😇😉🤣 😜🤐 🤣😅🤫 😶😮‍💨😇😁😜🤑🤫 🤫🤥😜🤤😇 😁😅😀🥰😀😁🤣🤫🥰😉 😀😮‍💨🤑 😉🤫🤕😶🤫😮‍💨😁🤫😉 🤮😇🤣😅 😇🤥😀🥶🤫😉 🤐🥰😜🤥 🤑😇🤐🤐🤫🥰🤫😮‍💨🤣 🤗🤫😮‍💨🤑😜🥰😉 😁🫡🤑🥰 😮‍💨😀🤥🤫 🤑😀🤣🤫 😉😜😶🥰😁🤫 😀😮‍💨🤑 🤯🤫🥳🤮😜🥰🤑😉

🤐🫡😀🥶🥸😉🤥😇🫡🤫😎🤥😜🥰🤫😎😉🤥😇🫡🤫😎🤠😇🥶🥶🤫🥰🧐
```
We are also given this hint:
```
Breaking this teaches you some of the primative concepts professionals use to attack novel cryptographic algorithms. It also demonstrates in a primative way why we use established and tested ones for real applications. It also loosely relates to a concept called "known plaintext."
```

There appears to be spaces between sections of emojis, which seems like it might get word breaks. 

The first thing I did was run the problem though javascript to analyze how often each emoji appears.
```javascript
var emojis = `<PROBLEM>`;
var result = [...emojis].reduce((a, e) => { a[e] = a[e] ? a[e] + 1 : 1; return a }, {}); 
```
You will notice that the occurrences of five of the emojis are in double digits, whereas the occurrences of the rest are just single digits. I would bet that these five are `aeoiu`. You could solve this by going through and replacing the most frequent with `e`, the next most with the next most frequent English letter, all the way down. Using a substitution cipher brute-forcer helps speed up the process, but you will have to replace emoji with a character so it doesn't mess up. Keep in mind the final flag format will start with "`flag{`", have "`_`" for word-breaks throughout, and end with "`}`".

<details>
<summary>Solution</summary>

```
flag{smile_more_smile_bigger}
```
</details>

<br/><br/><br/><br/>
# ACU2N, Matchmaker

Problem:
```
Dg0DDxoRBz4PHQIKNxIbBQwHHBMbFQ==
```
Provided information:
```
There are a variety of symmetric cryptosystems out there, but most of them involve a logic block called a XOR. The key is "hab"(UTF8). We're giving you the key and the algorithm, how hard can it be?
```

For this one we will use CyberChef. One important thing to remember on this problem is to decode it from Base64 before decoding the XOR. Drag in a `From Base64` module, then drag in the `XOR` module. Type in the key "`hab`". Click the drop-down on the right and set the key format to `UTF-8`. 


<details>
<summary>Solution</summary>

```
flag{so_much_symmetry}
```
</details>

<br/><br/><br/><br/>
# KYMV9, Hancock

Problem:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxMjM0NTY3ODkwLCJhZG1pbiI6ZmFsc2V9.QR_da_OHe58LBwBRt5S_aTcbMkBhEFqJkFn7zUq7Yyc
```
Message:
```
I stole this session token from someone and it looks like all I need to do is change admin to true for all the power... no idea who signed it though... can you figure out the secret for me so that we can get some pwnage going?

The secret for this token is somewhere in the RockYou wordlist
```

You can decode and view the different parts of the token at https://jwt.io/

After a bit of googling, we find this is the command to crack an `HS256 JWT` token:
```bash
hashcat -m 16500 -a0 <JWT>
```
<details>
<summary>Solution</summary>

```
ghosthunter
```
</details>

<br/><br/><br/><br/>
# TSIOQ, Trending
Problem:
```
b18f21b19e0f86b22d218c86e182214b867b36212576b2617e8c03862d369e
```

Message:
```
All the existing hashing algorithms are dumb, why give me a fixed length? If I give you more input you should give me even more output, its only fair! I wrote a new hashing algorithm that improves on the best of the best (MD5)! Check it out and see if you can break it (you probably can't)!

the flag is all lowercase ascii characters, curly brackets and underscores
```

[Attached](https://qualifier.hackabit.com/files/7e9639fa534d17b14f2d0e9f297b2cd6/hashbrown.py?token=eyJ1c2VyX2lkIjoxOTAsInRlYW1faWQiOm51bGwsImZpbGVfaWQiOjIyfQ.ZBynzw.r2AiDpHdI-cSCIeQa54QWtUhJYg) is python code that creates the hash. It looks like when you run it, it creates a five character long string of numbers (the code calls it "`one_time_pad_or_something`") which is used as a character code offset before putting the character through an MD5 hash. 

So the first thing we need to do is determine the offset string. We can do this because we know the first 5 characters of the solution already, "`flag{`".

Here is a function to copy the code's method of "hashing" using the string of characters:
```python
def hash(one_time_pad_or_something, str):
    result = ""
    for index, character in enumerate(str):
        calculated_character = chr(ord(character) - int(one_time_pad_or_something[index % 5]))
        full_md5_hash = hashlib.md5(calculated_character.encode('ascii'))
        result += full_md5_hash.hexdigest()[0:2]
    return result
```

And here is the code that will brute-force the pad. Technically it would be faster to do each character individually, but this was faster to code and shouldn't take too long anyways.
```python
for pad in range(10000, 99999): # for all 5 character pads
    pad = pad.__str__()         # the hash function takes it in as a string
    result = hash(pad, "flag{") # hash
    if result == "b18f21b19e":  # if this is the first part of the encrypted text, print and end
        print(pad)
        break
    print(result + " | " + pad)
```

This will run for a few seconds, and then stop after printing the pad, `76785`.

With the pad, we can now solve the full hash:
```python
known = "flag{" # this will store all the characters we have found so far
fullHash = "0f86b22d218c86e182214b867b36212576b2617e8c03862d369e" # the unsolved problem
knownHash = "b18f21b19e" # this will store all of the hashes we have found so far
pad = "76785"            # the pad
characters = 'abcdefghijklmnopqrstuvwxyz_{}' # all characters that could be in the flag

for i in range(0, len(fullHash), 2): # for each part of the flag
    chunk = fullHash[i:i+2]          # the chunk we are solving for
    goal = knownHash + chunk         # the entire chunk we are solving for
    found = False
    while not found:
        for char in characters:              # for each possible character
            print("testing " + char)
            testHash = hash(pad, known+char) # hash what we know and the character
            if testHash == goal:             # if this is the first part of the full hash
                known += char                # add the character to what we know
                print(known)
                knownHash = goal             # we know the solution to what we just solved for
                found = True
                break
```

<details>
<summary>Solution</summary>

```
flag{dont_roll_your_own_crypto}
```
</details>

<br/><br/><br/><br/>
# 89C4R, Powerhouse

Problem:
```
N = 6176128969 e = 1187
```
Message;
```
Here is an RSA key, sort of; provide p and q as p;q, like if p was 11 an q was 7, the flag would be 11;7.
```
After some googling about how RSA encryption works, we find tha `N` is `p*q`, and that they are both primes. 

So we will just go through all the primes, until we find one that `N` is evenly divisible by. Then to find the other prime, we will divide `N` by the prime we just found:
```javascript
function nextPrime(value) {
    // https://stackoverflow.com/questions/17389350/prime-numbers-javascript
    if (value > 2) {
        var i, q;
        do {
             i = 3;
             value += 2;
             q = Math.floor(Math.sqrt(value));
             while (i <= q && value % i) {
                 i += 2;
             }
        } while (i <= q);
        return value;
    }
    return value === 2 ? 3 : 2;
}
var found = false;
var prime = 1;
while (!found) {
    prime = nextPrime(prime);
    if (6176128969 % prime == 0) {
        found = true;
        console.log(`q: ${prime}, p: ${6176128969/prime}`);
    }
}
```
<details>
<summary>Solution</summary>

```
545161;11329
```
</details>

<br/><br/><br/><br/>
# 89C4R, Powerhouse

Problem:
```
320f5cef77246cdce15f9b66e9e4f3ad22f506f9cd28d85e7ccc8839b301e736
```
Message:
```
Crack this pin code. It's between 4-8 characters and all numeric.
```

A good first step would be to use a [hash identifier](https://hashes.com/en/tools/hash_identifier) to figure out what type of hash this is. In this case, it's `SHA256`.

One way to solve this is with John the Ripper:
```bash
echo "320f5cef77246cdce15f9b66e9e4f3ad22f506f9cd28d85e7ccc8839b301e736" > hash.txt
john --format=raw-sha256 --mask=?d?d?d?d?d?d?d?d --min-length=4 --max-length=8 hash.txt
```

A much faster way would be to any hash-cracking website, which searches their database for the hash. Typically that is much faster than doing it yourself.
<details>

<summary>Solution</summary>

```
05593620
```
</details>


