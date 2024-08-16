valid = True
not_valid = False

print(valid)
print(not_valid)

	# True
	# False


print(valid == True)
print(not_valid == True)

	# True
	# False


print(valid != True)
print(not_valid != True)

	# False
	# True


print(not valid)
print(not not_valid)

	# False
	# True


print((10 < 9) == True)
print((10 == 10) == True)
print((10 != 10) == True)
print((10 >= 10) == True)
print((10 <= 10) == True)
print((10 > 9) == True)

	# False
	# True 
	# False
	# True 
	# True 
	# True


print((10 < 9))
print((10 == 10))
print((10 != 10))
print((10 >= 10))
print((10 <= 10))
print((10 > 9))

	# False
	# True
	# False
	# True
	# True
	# True


print("-----")

	# -----


print(10 > 5 and 10 < 5)
print(10 > 5 or 10 < 5)

	# False
	# True


print(bool(0))
print(bool(1))

	# False
	# True


print(bool(0) == False)
print(bool(1) == True)

	# True
	# True


print(10 + 10)
print(10 - 10)
print(10 / 10)
print(10 // 10)

	# 20
	# 0
	# 1.0
	# 1


print(10 / 3)
print(10 // 3)
print(10 % 3)

	# 3.3333333333333335
	# 3
	# 1


print(10 * 10)
print(10 ** 10)
print(10 % 10)

	# 100
	# 10000000000
	# 0


x = 10
print(x)
x = x + 1
print(x)
x += 1
print(x)
x -= 1
print(x)
x *= 5
print(x)
x /= 5
print(x)

	# 10
	# 11
	# 12
	# 11
	# 55
	# 11.0


x = 13
print(bin(x))
print(bin(x)[2:].rjust(4,"0"))

	# 0b1101
	# 1101


y = 5
print(bin(y)[2:].rjust(4,"0"))

	# 0101


print(bin(x & y)[2:].rjust(4,"0"))

	# 0101


print(x & y)

	# 5


print(bin(x | y)[2:].rjust(4,"0"))

	# 1101


x = 13
print(bin(x >> 1)[2:].rjust(4,"0"))

	# 0110


