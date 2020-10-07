import os
import shutil
from FileStorage import File
from FileStorage import FileStorage
from FileEncryptor import BMPEncryptor, BMPImage
from FileEncryptor.Cipher import AES_CBC

KEY = b"0123456789abcdef"
IV = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"

def __enc_file__(file_name, new_file_name):
    bytes_gen = BMPImage(file_name)
    cipher = AES_CBC(KEY)
    cipher.set_param(0, IV)
    file_enc = BMPEncryptor(cipher, buffer_size= 2 * 1024 ** 2)
    file_enc.encrypt_to(bytes_gen, new_file_name)

def main():
    if len(os.sys.argv) != 2:
        print("Invalid command! Exit")
        return

    imgs_dir = os.sys.argv[1]

    print("Remove directory previous Storage... ", end = "")
    try:
        shutil.rmtree("Storage")
    except FileNotFoundError:
        pass
    print("done")

    fs = FileStorage("Storage", n_splits= 100)
    
    N = len(list(os.listdir(imgs_dir)))
    n = 0
    print("Store file to Storage ...")
    for file in os.listdir(imgs_dir):
        path = os.path.join(imgs_dir, file)
        print("\rProcess {:2.2f}% [{}/{}]".format((n + 1)/N * 100, n + 1, N), end = "")
        if os.path.isfile(path):
            try:
                __enc_file__(path, ".tmp")
            except:
                continue
            last_bytes = File.get_elements_at_the_end(".tmp", 100)
            new_path = fs.create_new_path(last_bytes)
            shutil.move(".tmp", new_path)
            fs.save_info(new_path)
            n += 1

if __name__ == "__main__":
    #main()
    fs = FileStorage("Storage", 100)
    last_bytes = File.get_elements_at_the_end("32553426708", 100)
    print(fs.create_new_path(last_bytes))