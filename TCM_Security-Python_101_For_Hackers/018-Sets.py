set1 = {"a", "b", "c"}
print(set1)
print(type(set1))

    # {'a', 'b', 'c'}
    # <class 'set'>


set2 = {"a", "a", "a"}
print(set2)
print(len(set2))

    # {'a'}        
    # 1


set3 = {"a", 0, True}
print(set3)

    # {0, True, 'a'}


set4 = set(("b", 1, False))
print(set4)

    # {'b', 1, False}


set1.add("d")
print(set1)

    # {'a', 'c', 'b', 'd'}


set3.update(set4)
print(set3)

    # {0, True, 'a', 'b'}


list1 = ["a", "b", "c"]
set4 = {4, 5, 6}
print(list1)
print(set4)

    # ['a', 'b', 'c']
    # {4, 5, 6}


set4.update(list1)
print(set4)

    # {4, 5, 6, 'c', 'a', 'b'}


set5 = {4, 5, 6}
set6 = set4.union(set4)
print(set6)

    # {4, 5, 6, 'c', 'a', 'b'}


set4.discard(4)
print(set4)

    # {'b', 5, 6, 'c', 'a'}


set4.discard(4)
print(set4)

    # {'b', 5, 6, 'c', 'a'}


print(set1)
set1.pop()
print(set1)

    # {'a', 'b', 'c', 'd'}
    # {'b', 'c', 'd'}

