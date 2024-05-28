# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio, os

from utils import read_file_as_bytes, valida_cert, mkpair, unpair, p, g

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography import x509

conn_port = 8443
max_msg_size = 9999
debug = False
password = b'1234'

private_key_rsa = load_pem_private_key(
    read_file_as_bytes('MSG_CLI1.key'), 
    password, 
    default_backend()
)

client_crt_bytes = read_file_as_bytes('MSG_CLI1.crt')

parameters = dh.DHParameterNumbers(p, g).parameters()
private_key_dl = parameters.generate_private_key()
public_key_dl = private_key_dl.public_key()

pem_dl = public_key_dl.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)


class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        
    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        
        self.msg_cnt += 1
        
        print('Received (%d): %r' % (self.msg_cnt , msg.decode()))
        print('Input message to send (empty to finish)')
        
        new_msg = input().encode()
        return new_msg if len(new_msg)>0 else None

#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#        

async def tcp_echo_client():
    
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    
    # Enviar public key serializada
    
    writer.write(pem_dl) 
    await writer.drain()
    
    # Receber public key, signature, e certificado do server 
    
    msg = await reader.read(max_msg_size)
    key_sig_pair, server_cert_bytes = unpair(msg)
    public_server_key_dl_bytes, server_signature = unpair(key_sig_pair)
    
    # Validar certificado e signature
    
    cert = x509.load_pem_x509_certificate(server_cert_bytes)  # precisaria de backend=defaultbackend() como argumento caso se quisesse verificar 
    if not valida_cert(cert):                                 # caso se quisesse verificar (x509.ExtensionOID.EXTENDED_KEY_USAGE,
        if debug: print("Cerificado inválido")                # lambda ext: x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in ext)
        return
    
    public_server_key_rsa = cert.public_key()
    message = public_server_key_dl_bytes +  pem_dl
    try:
        public_server_key_rsa.verify(
            server_signature,
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
    
    # Enviar signature e certificado
    
    message = pem_dl + public_server_key_dl_bytes 
    signature = private_key_rsa.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256() 
    )
    
    writer.write(mkpair(signature, client_crt_bytes))
    
    # --------
    
    public_server_key_dl = load_pem_public_key(public_server_key_dl_bytes)
    shared_key = private_key_dl.exchange(public_server_key_dl)    
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
    )
    
    key = hkdf.derive(shared_key)
    
    msg = client.process() 
    while msg:
        
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, msg, password)
        
        writer.write(nonce + ct)
                
        msg = await reader.read(max_msg_size)
        if msg :
            msg = client.process(msg)
        else:
            break
        
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()


def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()
