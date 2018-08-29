## encrypt-demo

>数据加解密的相关Demo

### Base64Demo
![使用流程图](http://static.open-open.com/lib/uploadImg/20140412/20140412114509_299.jpg)
* 单向加密
* BASE加密后产生的字节位数是8的倍数，如果不够位数以=符号填充

### MD5Demo
![使用流程图](http://static.open-open.com/lib/uploadImg/20140412/20140412114509_236.jpg)
* message-digest algorithm 5 消息摘要算法
* 通常将MD5产生的字节数组交给BASE64再加密一把，得到相应的字符串。

### SHA
![使用流程图](http://static.open-open.com/lib/uploadImg/20140412/20140412114510_468.jpg)
>SHA(Secure Hash Algorithm，安全散列算法），数字签名等密码学应用中重要的工具，被广泛地应用于电子商务等信息安全领域。虽然，SHA与MD5通过碰撞法都被破解了， 但是SHA仍然是公认的安全加密算法，较之MD5更为安全。 

### HMAC
>HMAC(Hash Message Authentication Code，散列消息鉴别码，基于密钥的Hash算法的认证协议。消息鉴别码实现鉴别的原理是，用公开函数和密钥产生一个固定长度的值作为认证标识，用这个 标识鉴别消息的完整性。使用一个密钥生成一个固定大小的小数据块，即MAC，并将其加入到消息中，然后传输。接收方利用与发送方共享的密钥进行鉴别认证 等。 

![使用流程图](http://static.open-open.com/lib/uploadImg/20140412/20140412114510_304.jpg)


![使用流程图]()