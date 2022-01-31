import os
from PIL import Image
import pefile
import numpy as np

def to_png(binaryValues):
    width = 0
    if (width == 0):
        size = len(binaryValues)

        if (size < 10240):
            width = 32
        elif (10240 <= size <= 10240*3):
            width = 64
        elif (10240*3 <= size <= 10240*6):
            width = 128
        elif (10240*6 <= size <= 10240*10):
            width = 256
        elif (10240*10 <= size <= 10240*20):
            width = 384
        elif (10240*20 <= size <= 10240*50):
            width = 512
        elif (10240*50 <= size <= 10240*100):
            width = 768
        else:
            width = 1024

        height = int(size/width) + 1

        image = Image.new('L', (width, height))

        image.putdata(binaryValues)

        print(image)

        image = image.resize((256, 256))

        image_name = rfile+ "(header).png"

        save_path = path + '/header_section_img/' + cate + '_header_section_img/'

        image.save(save_path + image_name)

        print(image_name + "_header_Greyscale_image")


# opcode header 추출
def opcode_Get(file_path):
    try:
        pe = pefile.PE(file_path,fast_load=True)
        entry = pe.DOS_HEADER.e_lfanew
        end = entry + 0xF7
        print(hex(entry))
        print(hex(end))
        raw_data = pe.__data__[entry:end]
        data = raw_data.hex()
        length = 2
        split_data = [int(''.join(x), 16) for x in zip(*[list(data[z::length]) for z in range(length)])]
        #return raw_data
        return np.nan_to_num(split_data)
            
    except: 
        return
        


Category = ['DarkSide', 'Gandcrab', 'Maze', 'NetWalker', 'Ryuk', 'Sodinokibi']

for cate in Category:
    path = '/home/kali/Desktop/Ransomware_Research/Samples(1101)/' + cate + '/'

    file_list = os.listdir(path)

    for rfile in file_list:
        filename = path + rfile
        print(filename)

        binaryValues = []
        file = open(filename, 'rb')
        data = file.read(1)
        while data != b"":
            try:
                binaryValues.append(ord(data))
            except TypeError:
                pass
            data = file.read(1) 
        
        print(str(binaryValues[0]) + ' ' + str(binaryValues[1]))
        
        if binaryValues[0] == 77 and binaryValues[1] == 90:
            try:
                header_section = opcode_Get(filename)
                print(header_section)
                to_png(header_section)
            
            except Exception as e:
                    print("error msg : ", e)


# 코드 참고
# https://m.blog.naver.com/PostView.naver?isHttpsRedirect=true&blogId=stop2y&logNo=221502904904