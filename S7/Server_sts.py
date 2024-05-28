# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio

from utils import mkpair, unpair, read_file_as_bytes, valida_cert, p, g

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509

debug = False
conn_cnt = 0
conn_port = 8443
max_msg_size = 9999
password = b'1234'


private_key_rsa = load_pem_private_key(
    read_file_as_bytes('MSG_SERVER.key'), 
    password, 
    default_backend()
)

server_crt_bytes = read_file_as_bytes('MSG_SERVER.crt')

parameters = dh.DHParameterNumbers(p, g).parameters()
private_key_dl = parameters.generate_private_key()
public_key_dl = private_key_dl.public_key()

pem_dl = public_key_dl.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)


class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.shared_key = None
        self.key = None
        
    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
            
        self.msg_cnt += 1
            
        nonce = msg[:12]
        ct = msg[12:]
        
        aesgcm = AESGCM(self.key)
        decrypted = aesgcm.decrypt(nonce, ct, password)    
        
        txt = decrypted.decode()
        print('%d : %r' % (self.id,txt))
        new_msg = txt.upper().encode()
        
        return new_msg if len(new_msg)>0 else None


#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)

    data = await reader.read(max_msg_size);  # client public key
    public_client_key_dl_bytes = data
    
    message = pem_dl + public_client_key_dl_bytes
    signature = private_key_rsa.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    to_send = mkpair(mkpair(pem_dl, signature), server_crt_bytes)
    writer.write(to_send)
    await writer.drain()
    
    data = await reader.read(max_msg_size)  # receive sig + cert client
    client_signature, client_cert_bytes = unpair(data)

    # Validar
    
    client_cert = x509.load_pem_x509_certificate(client_cert_bytes)
    if not valida_cert(client_cert):
        if debug: print("Certificado inválido")
        return
    
    public_client_key_rsa = client_cert.public_key()
    try:
        message = public_client_key_dl_bytes +  pem_dl
        public_client_key_rsa.verify(
            client_signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        if debug: print("Assinatura inválida")
        return
    
    public_client_key_dl = load_pem_public_key(public_client_key_dl_bytes)
    shared_key = private_key_dl.exchange(public_client_key_dl)
    
    # --------
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
    )
    
    key = hkdf.derive(shared_key)
    srvwrk.key = key
    
    data = await reader.read(max_msg_size)
    
    while True:
        if not data: continue
        if data[:1]==b'\n': break
        data = srvwrk.process(data)
        if not data: break
        writer.write(data)
        await writer.drain()
        data = await reader.read(max_msg_size)
        
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.new_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')


run_server()
