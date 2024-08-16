dict1 = {"a":1, "b":2, "c":3}
print(dict1)
print(type(dict1))
print(len(dict1))

    # {'a': 1, 'b': 2, 'c': 3}
    # <class 'dict'>
    # 3


print(dict1["a"])
print(dict1.get("a"))

    # 1
    # 1


print(dict1.keys())
print(dict1.values())
print(dict1.items())

    # dict_keys(['a', 'b', 'c'])
    # dict_values([1, 2, 3])
    # dict_items([('a', 1), ('b', 2), ('c', 3)])


dict1["a"] = 1
print(dict1)

    # {'a': 1, 'b': 2, 'c': 3}


dict1["d"] = 4
print(dict1)

    # {'a': 1, 'b': 2, 'c': 3, 'd': 4}


dict1["a"] = 0
print(dict1)

    # {'a': 0, 'b': 2, 'c': 3, 'd': 4}


dict1.update({"a": 1})
print(dict1)

    # {'a': 1, 'b': 2, 'c': 3, 'd': 4}


dict1.pop("d")
print(dict1)

    # {'a': 1, 'b': 2, 'c': 3}


del dict1['c']
print(dict1)

    # {'a': 1, 'b': 2}


dict1['c'] = {"a":1, "b":2}
print(dict1)

    # {'a': 1, 'b': 2, 'c': {'a': 1, 'b': 2}}


dict2 = {}
print(dict2)

    # {}


dict3 = dict()
print(dict3)

    # {}

