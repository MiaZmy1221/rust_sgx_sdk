import re
import os

os.system('wat2wasm module5.wast -o test.wasm')

with open("test.wasm", "rb") as binary_file:
    # Read the whole file at once
    data = binary_file.read()
    print data.encode('hex')

list = re.findall('..', data.encode('hex'))
print(list)

result = ""
for i, x in enumerate(list):
    if i ==0:
        result = result + '0x' + x
    else:
        result = result + ', 0x' + x
print(result)    

fw = open("result.txt", "w")
fw.write(result)
