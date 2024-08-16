f = open('top20.txt')
print(f)

    # <_io.TextIOWrapper name='top20.txt' mode='r' encoding='cp1252'>


f = open('top20.txt', 'rt')
print(f)

    # <_io.TextIOWrapper name='top20.txt' mode='rt' encoding='cp1252'>


print(f.readlines())
print(f.readlines())

    # ['JAMES\n', 'JOHN\n', 'ROBERT\n', 'MICHAEL\n', 'WILLIAM\n', 'DAVID\n', 'RICHARD\n', 'CHARLES\n', 'JOSEPH\n', 'THOMAS\n', 'CHRISTOPHER\n', 'DANIEL\n', 'PAUL\n', 'MARK\n', 'DONALD\n', 'GEORGE\n', 'KENNETH\n', 'STEVEN\n', 'EDWARD\n', 'BRIAN\n']
    # []


f.seek(0)
print(f.readlines())

    # ['JAMES\n', 'JOHN\n', 'ROBERT\n', 'MICHAEL\n', 'WILLIAM\n', 'DAVID\n', 'RICHARD\n', 'CHARLES\n', 'JOSEPH\n', 'THOMAS\n', 'CHRISTOPHER\n', 'DANIEL\n', 'PAUL\n', 'MARK\n', 'DONALD\n', 'GEORGE\n', 'KENNETH\n', 'STEVEN\n', 'EDWARD\n', 'BRIAN\n']


f.seek(0)
for line in f:
    print(line.strip())

    # JAMES
    # JOHN
    # ROBERT
    # MICHAEL
    # WILLIAM
    # DAVID
    # RICHARD
    # CHARLES
    # JOSEPH
    # THOMAS
    # CHRISTOPHER
    # DANIEL
    # PAUL
    # MARK
    # DONALD
    # GEORGE
    # KENNETH
    # STEVEN
    # EDWARD
    # BRIAN


f.close()


f = open("test.txt", "w")
f.write("test line!")
f.close()

    # this created test.txt
    # PS D:\Vault> cat test.txt
    # test line!


f = open("test.txt", "a")
f.write("test line two!")
f.close()

    # PS D:\Vault> cat test.txt
    # test line two!


print(f.name)
print(f.closed)
print(f.mode)

    # test.txt
    # True
    # a


with open('rockyou.txt', encoding='latin-1') as f:
    for line in f:
        pass

# Your code snippet is opening a file named rockyou.txt with the latin-1 encoding and iterating over each line in the file. However, the loop doesn't perform any actions with the lines read. This will print each line from the file, stripping any leading or trailing whitespace.


