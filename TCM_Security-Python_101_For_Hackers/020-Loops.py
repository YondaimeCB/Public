a = 1
print(a)
a += 1
print(a)
a += 1
print(a)
a += 1
print(a)
a += 1
print(a)

    # 1
    # 2
    # 3
    # 4
    # 5


a = 1
while a < 5:
    a += 1
    print(a)

    # 2
    # 3
    # 4
    # 5


for i in [0, 1, 2, 3, 4]:
    print(i+6)

    # 6
    # 7
    # 8
    # 9
    # 10


print("---")


for i in range(5):
    print(i+6)

    # 6
    # 7
    # 8
    # 9
    # 10


for i in range(3):
    for j in range(3):
        print(i,j)

    # 0 0
    # 0 1
    # 0 2
    # 1 0
    # 1 1
    # 1 2
    # 2 0
    # 2 1
    # 2 2


print("---")


for i in range(5):
    if i == 2:
        break
    print(i)

    # 0
    # 1


for i in range(5):
    if i == 2:
        continue
    print(i)

    # 0
    # 1
    # 3
    # 4


print("---")


for i in range(5):
    if i == 2:
        pass
    print(i)

    # 0
    # 1
    # 2
    # 3
    # 4


for c in "string":
    print(c)

    # s
    # t
    # r
    # i
    # n
    # g


for key, value in {"a":1, "b":2, "c":3}.items():
    print(key, value)

    # a 1
    # b 2
    # c 3

