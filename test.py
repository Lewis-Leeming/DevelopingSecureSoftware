import rsa

private_key = (32075, 756731)
public_key = (181763, 756731)



message = "hkajsdhkjashd"


enc = rsa.encrypt(private_key, message)

print(enc)



dec = rsa.decrypt(public_key, enc)

print(dec)