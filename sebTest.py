from sebConfigUtils import *




    
if __name__ == '__main__':
    password="123"
    with open("Dawson.seb", 'rb') as f:
        seb_file_data = f.read()
        
    decrypted = decrypt_seb_config(seb_file_data, password=password)
    # ck = generate_config_key(decrypted)
    # print(f"Config Key: {ck}")
    # reencrypted = encrypt_seb_config(decrypted, password=password)
    # with open("Dawson_reencrypted.seb", 'wb') as f:
    #     f.write(reencrypted)
    # create_seb_from_json("configSEB.json", "output.seb", password=password)