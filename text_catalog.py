class txt_window:
    title : str = 'Prácticas Criptograhy'
    df_color : str = 'blue'
    width : int = 720
    height : int = 520
    app_name : str = 'Criptógrafo 🏛️'
    app_icon : str = 'src/app.png'

class txt_main_menu:
    title = 'Menú principal'
    df_color : str = 'red'

class txt_practica0:
    title = 'Práctica 6 - Garzón & Sánchez'
    df_color : str = 'white'

    class Who:
        Alice = 'Alice'
        Bob = 'Bob'
    
    class dh:
        gen = 2
        keysiz = 2048
        dh_params = 'dhparams.pem'
        a_param = 'a.pem'
        b_param = 'b.pem'
        iva_param = 'iva.pem'
        ivb_param = 'ivb.pem'
        K_param = 'K'
        IV_param = 'IV'
        Secret_K = 'Secret'
        Secret_IV = f'{Secret_K}_IV'

    class rsa:
        bits = 4096
        maxbytes = int(bits//8)
        privname = 'rsa_private.txt'
        pubname = 'rsa_public.txt'

    class mode:
        cipher = False
        decipher = True
        ecb = 'ECB'
        cbc = 'CBC'
        cfb = 'CFB'
        ofb = 'OFB'
        opmode = [ecb, cbc, cfb, ofb]

    class layout:
        passw_sz = (400, 30)
        initv_sz = (400, 30)
        btn_sz = (220, 60)
        mod_sz = (35, 25)
        log_sz = (600, 150)
        ingrid_spacin = 5
        grid_spacin = 3

    class log:
        filewerr = '** Error de escritura en el archivo:'
        fileerr = '** Importe de nuevo el archivo --\nNo se pudo abrir el archivo'
        initvign = '** Modo ECB no necesita vector de inicialización ... se ignorará IV'
        routerr = '** La ruta no es valida:'
        key = '** Contraseña utilizada: '
        route = '** Ruta de archivo:'
        file = '** Archivo importado exitosamente como:\n'
        expf = '** Archivo exportado existosamente como:\n'
        wrongk = '** LLave incorrecta! / O el archivo ya es texto en claro!'

    class icn:
        fopen = 'src/open.png'
        fexp = 'src/export.png'
        fciph = 'src/cipher.png'
        fdciph = 'src/decipher.png'

    class prompt:
        key = 'Introduzca una contraseña'

    class cfg:
        endian = 'little'
        txt_encode = 'utf-8'
        key_len = 16
        bmp_head_size = 54
        bmp_head = bmp_head_size
        bmp_restof = -1
        bmp_ext = '.bmp'
        accept_img = ('.bmp', 'jpg', 'png')
        salt = b'sal'
        pepper = b'pimienta'

    class btns:
        meta_mode = 'mode-btn'
        as_cipher = 'Modo: Cifrar'
        as_decipher = 'Modo: Descifrar'
        import_file = 'Importar archivo'
        action = 'Comenzar acción'

