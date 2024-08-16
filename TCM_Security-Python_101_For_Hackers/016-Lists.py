list1 = ["A", "B", "C", "D", "E", "F"]
print(list1)

    # ['A', 'B', 'C', 'D', 'E', 'F']


list2 = ["A", 1, 2.0, ["A"], [], list(), ("A"), False]
print(list2)
print(type(list2))

    # ['A', 1, 2.0, ['A'], [], [], 'A', False]
    # <class 'list'>


print(list1[0])
print(list1[-1])
print(list2[3][0])
print(list2[3][-1])

    # A
    # F
    # A
    # A


list1[0] = "X"
print(list1)

    # ['X', 'B', 'C', 'D', 'E', 'F']


del list1[0]
print(list1)

    # ['B', 'C', 'D', 'E', 'F']


list1.insert(0, "A")
print(list1)

    # ['A', 'B', 'C', 'D', 'E', 'F']


del list1[0]
print(list1)

    # ['B', 'C', 'D', 'E', 'F']


list1 = ["A"] + list1
print(list1)

    # ['A', 'B', 'C', 'D', 'E', 'F']


list1.append("G")
print(list1)

    # ['A', 'B', 'C', 'D', 'E', 'F', 'G']


print(max(list1))
print(min(list1))

    # G
    # A


print(list1.index("C"))
print(list1[list1.index("C")])

    # 2
    # C


list1.reverse()
print(list1)

    # ['G', 'F', 'E', 'D', 'C', 'B', 'A']


list1 = list1[::-1]
print(list1)

    # ['A', 'B', 'C', 'D', 'E', 'F', 'G']


print(list1.count("A"))
list1.append("A")
print(list1)
print(list1.count("A"))

    # 1
    # ['G', 'F', 'E', 'D', 'C', 'B', 'A', 'A']
    # 2


list1.pop()
print(list1)

    # ['G', 'F', 'E', 'D', 'C', 'B', 'A']


list3 = ["H", "I", "J"]
print(list3)

    # ['H', 'I', 'J']


list1.extend(list3)
print(list1)

    # ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J']


list1.clear()
print(list1)

    # []


list4 = [8, 12, 5, 6, 17, 2]
print(list4)

    # [8, 12, 5, 6, 17, 2]


list4.sort()
print(list4)

    # [2, 5, 6, 8, 12, 17]


list4.sort(reverse=True)
print(list4)

    # [17, 12, 8, 6, 5, 2]


list5 = list4
print(list5)
print(list4)

    # [17, 12, 8, 6, 5, 2]
    # [17, 12, 8, 6, 5, 2]


list5[2] = "X"
print(list5)
print(list4)

    # [17, 12, 'X', 6, 5, 2]
    # [17, 12, 'X', 6, 5, 2]


list6 = list4.copy()
print(list4)
print(list6)

    # [17, 12, 'X', 6, 5, 2]
    # [17, 12, 'X', 6, 5, 2]


list6[2] = "A"
print(list6)
print(list4)

    # [17, 12, 'A', 6, 5, 2]
    # [17, 12, 'X', 6, 5, 2]


list7 = ["1", "2", "3"]
print(list7)

    # ['1', '2', '3']


list8 = list(map(float, list7))
print(list8)

    # [1.0, 2.0, 3.0]

