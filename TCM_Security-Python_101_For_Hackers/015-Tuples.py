tuple_items = ("item1", "item2", "item3")
print(tuple_items)
print(type(tuple_items))

	# ('item1', 'item2', 'item3')
	# <class 'tuple'>


tuple_numbers = (1, 2, 3)
print(tuple_numbers)
print(type(tuple_numbers))

	# (1, 2, 3)
	# <class 'tuple'>


tuple_repeat = ('Combine!',) * 4
print(tuple_repeat)
print(type(tuple_repeat))

	# ('Combine!', 'Combine!', 'Combine!', 'Combine!')
	# <class 'tuple'>


tuple_combined = tuple_items + tuple_numbers
print(tuple_combined)
print(type(tuple_combined))

	# ('item1', 'item2', 'item3', 1, 2, 3)
	# <class 'tuple'>


item1, item2, item3 = tuple_items
print(item1)
print(item2)
print(item3)

	# item1
	# item2
	# item3


print("item2" in tuple_items)
print("item3" in tuple_items)
print("item4" in tuple_items)

	# True
	# True
	# False


print(tuple_items.index("item2"))

	# 1


tuple_items = ("item1", "item2", "item3")
print(tuple_items[0])
print(tuple_items[1])
print(tuple_items[2])

	# item1
	# item2
	# item3


print(len(tuple_items))

	# 3


print(tuple_items[-1])
print(tuple_items[-2])

	# item3
	# item2


print(tuple_items[0:2])

	# ('item1', 'item2')


string1 = "I am a string!"
print(string1[0:4])
print(string1[-1])

	# I am
	# !

