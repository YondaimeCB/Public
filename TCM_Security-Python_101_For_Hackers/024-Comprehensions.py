list1 = ['a', 'b', 'c']
print(list1)

    # ['a', 'b', 'c']


list2 = [x for x in list1]
print(list2)

    # ['a', 'b', 'c']


list3 = [ x for x in list1 if x == 'a']
print(list3)

    # ['a']


list4 = [x for x in range(5)]
print(list4)

    # [0, 1, 2, 3, 4]


list5 = [hex(x) for x in range(5)]
print(list5)

    # ['0x0', '0x1', '0x2', '0x3', '0x4']


list6 = [hex(x) if x > 0 else "X" for x in range(5)]
print(list6)

    # ['X', '0x1', '0x2', '0x3', '0x4'] 


list7 = [x * x for x in range(5)]
print(list7)

    # [0, 1, 4, 9, 16]

list8 = [x for x in range(5) if x == 0 or x == 1]
print(list8)

    # [0, 1]


list9 = [[1,2,3],[4,5,6],[7,8,9]]
print(list9)

    # [[1, 2, 3], [4, 5, 6], [7, 8, 9]]


list10 = [y for x in list9 for y in x]
print(list10)

    # [1, 2, 3, 4, 5, 6, 7, 8, 9]


set1 = {x + x for x in range(5)}
print(set1)

    # {0, 2, 4, 6, 8}


list11 = [c for c in "string"]
print(list11)

    # ['s', 't', 'r', 'i', 'n', 'g']


print("".join(list11))
print("-".join(list11))

    # string
    # s-t-r-i-n-g

