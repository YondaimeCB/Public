print(1)
# print(2)

    # IndentationError: unexpected indent


# f = open("asdasdasdasd")

    # FileNotFoundError: [Errno 2] No such file or directory: 'asdasdasdasd'


try:
    f = open("adsadsadsads")
except:
    print("the file does not exist!")

    # the file does not exist!


try:
    zxczvzxczczczc
except:
    print("the file does not exist!")

    # the file does not exist!


try:
    f = open("adsadsadsads")
except Exception as e:
    print(e)

    # [Errno 2] No such file or directory: 'adsadsadsads'


try:
    adsadsadsads
except Exception as e:
    print(e)

    # name 'adsadsadsads' is not defined


try:
    f = open("adsadsadsads")
except FileNotFoundError:
    print("the file does not exist!")
except Exception as e:
    print(e)

    # the file does not exist!


try:
    qweqweqweqe
    f = open("adsadsadsads")
except FileNotFoundError:
    print("the file does not exist!")
except Exception as e:
    print(e)

    # name 'qweqweqweqe' is not defined


try:
    qweqweqweqe
    f = open("adsadsadsads")
except FileNotFoundError:
    print("the file does not exist!")
except Exception as e:
    print(e)
finally:
    print("this message!")

    # this message!


try:
    f = open("adsasdfsdsadsads")
except FileNotFoundError:
    print("the file does not exist!!")
except Exception as e:
    print(e)
finally:
    print("this message!!")

    # the file does not exist!!
    # this message!!


try:
    f = open("test.txt")
except FileNotFoundError:
    print("the file does not exist!!!")
except Exception as e:
    print(e)
finally:
    print("this message!!!")

    # this message!!!


n = 100
if n == 0:
    raise Exception("n can't be 0!")
print(1/n)

    # 0.01


# n = 0
# if n == 0:
#     raise Exception("n can't be 0!")
# print(1/n)

    # raise Exception("n can't be 0!")
    # Exception: n can't be 0!


# n = "asd"
# if n == 0:
#     raise Exception("n can't be 0!")
# print(1/n)

    # TypeError: unsupported operand type(s) for /: 'int' and 'str'


# n = "asd"
# if n == 0:
#     raise Exception("n can't be 0!")
# if type(n) is not int:
#     raise Exception("n must be an int!")
# print(1/n)

    # Exception: n must be an int!


n = 1
assert(n != 0)
print(1/n)

    # 1.0


# n = 0
# assert(n != 0)
# print(1/n)

    # AssertionError