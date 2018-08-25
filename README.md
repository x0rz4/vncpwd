与任何其他远程控制软件一样，VNC服务器可以受密码保护，以防止未经授权的用户控制服务器。保存在服务器上的密码使用DES加密，但不幸的是，该算法早已被破解。有许多第三方工具声称自动解密并显示VNC服务器密码，但大多数工具未更新以使用最新版本的VNC。根据我们测试的结果，Nirsoft的VNCPassView只能显示UltraVNC密码，Patrik Karlsson的VNCPwdump无法使用-s或-c开关显示RealVNC密码，而VNC Password Decryptor也无法在本地获取和解密VNC密码电脑。
这些自动VNC密码恢复工具不起作用，因为保存在计算机上的DES加密密码的位置已更改，并且未更新它们以从新路径读取。在这里，我们将指导您如何找到VNC加密密码，以及如何通过基于Web或通过命令行工具在本地手动解密它们。
找到加密的VNC密码
大多数VNC加密密码都保存在注册表中，而只有UltraVNC保存在INI文件中。以下是如何根据下面提供的注册表位置获取RealVNC的加密密码的示例。

1.单击“开始”按钮，在“搜索程序和文件”栏中键入regedit，然后按Enter键。

2.通过双击它展开HKEY_LOCAL_MACHINE文件夹并继续为SOFTWARE，RealVNC执行该操作，直到到达vncserver。

3.在右窗格中，您应该看到名为Password的注册表名称，类型为REG_SZ，数据是随机字符。您在Password中看到的随机字符是RealVNC的加密密码，请注意它以进行解密。

2.通过双击它展开HKEY_LOCAL_MACHINE文件夹并继续为SOFTWARE，RealVNC执行该操作，直到到达vncserver。

3.在右窗格中，您应该看到名为Password的注册表名称，类型为REG_SZ，数据是随机字符。您在Password中看到的随机字符是RealVNC的加密密码，请注意它以进行解密。

RealVNC
HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver
Value: Password

TightVNC
HKEY_CURRENT_USER\Software\TightVNC\Server
Value: Password or PasswordViewOnly

TigerVNC
HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4
Value: Password

UltraVNC
C:\Program Files\UltraVNC\ultravnc.ini
Value: passwd or passwd2

一旦获得加密的VNC密码，下一步就是解密它。在这里，我提供了要在脱机计算机上运行但需要从命令提示符运行的命令行工具。

解密加密的VNC密码

Luigi Auriemma的VNC密码解码器（vncpwd）工具可以解密经典的VNC DES加密方法。只需在命令行工具后嵌入加密密码，即可显示真实密码。要使用vncpwd，请单击“开始”按钮，在搜索栏中键入cmd，然后按Enter键。切换到vncpwd.exe所在的目录并运行以下commnad行：

阅读更多：https//Www.Raymond.Cc/Blog/Crack-Or-Decrypt-Vnc-Server-Encrypted-Password/




---------------------------------------------------------------------------------------------



Most of the VNCs encrypted password are saved in registry while only UltraVNC is saved in an INI file. Here is an example on how to get the encrypted password for RealVNC based on the registry location provided below.
1. Click the Start button, type regedit in the Search programs and files bar followed by pressing Enter.

2. Expand the HKEY_LOCAL_MACHINE folder by double clicking on it and continue doing that for SOFTWARE, RealVNC and until you reach vncserver.

3. At the right pane, you should see a registry name called Password with the type as REG_SZ and random characters for the data. The random characters you see for Password is the encrypted password for RealVNC and please take note of it for decryption.

RealVNC
HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver
Value: Password

TightVNC
HKEY_CURRENT_USER\Software\TightVNC\Server
Value: Password or PasswordViewOnly

TigerVNC
HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4
Value: Password

UltraVNC
C:\Program Files\UltraVNC\ultravnc.ini
Value: passwd or passwd2

Once you’ve got the encrypted VNC password, the next step is to decrypt it. Here we offer two choices which is the web based that is very easy to use but requires an internet connection to access it or a command line tool that works on an offline computer but requires to run from command prompt.

Decrypting The Encrypted VNC Password

The VNC Password Decoder (vncpwd) tool by Luigi Auriemma can decrypt classic VNC DES encryption method. Simply embed the encrypted password after the command line tool and the real password will be displayed. To use vncpwd, click Start button, type cmd at search bar and press Enter. Change to the directory where vncpwd.exe is located and run the following commnad line:

Read More: Https://Www.Raymond.Cc/Blog/Crack-Or-Decrypt-Vnc-Server-Encrypted-Password/

