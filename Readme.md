## 基于vim密码本


原理
```
输入正确密码后,解密文本文件,通过vim编辑文件，编辑完成后，在加密保存。
```

安装
```bash
# 1.下载源码
git clone https://github.com/try-fun/mypasswd

# 2. 安装
cd mypasswd && make install
```

使用方法
```bash
# bash中输入 mypasswd,按照提示输入密码,即可通过vim记录密码
~ mypasswd
Type a password:
```

