
## 构建
```shell
mvn clean package
```

## 运行TLCPServer

```shell
java -Dorg.conscrypt.useEngineSocketByDefault=false -cp  target/TLCPServer-0.1.0.jar demo.TLCPServer
```
