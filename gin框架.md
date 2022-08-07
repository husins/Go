# 基本服务

```go
package main

import (
    // 引入gin得包
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	// 创建路由
	r := gin.Default()
	// 绑定路由，并执行对应函数
	// gin.Context,封装了request和response
	r.GET("/", func(c *gin.Context) {
		// String将给定的字符串写入响应体。
		c.String(http.StatusOK, "hello world!")
	})
	// 监听端口，默认是8080
	r.Run(":8848")
}
```

# Gin路由

## 基本路由

- gin 框架中采用的路优酷是基于`httprouter`做的

### httprouter

```go
package main
 
import (
     "fmt"
     "github.com/julienschmidt/httprouter"
     "net/http"
     "log"
)
 
func Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
     fmt.Fprint(w, "Welcome!\n")
}
 
func Hello(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
     fmt.Fprintf(w, "hello, %s!\n", ps.ByName("name"))
}

func main() {
     router := httprouter.New()
     router.GET("/", Index)
     router.GET("/hello/:name", Hello)
 
     log.Fatal(http.ListenAndServe(":8080", router))
}
```

## Restful风格得API

- 域名：应该尽量将API部署在专用域名之下，如`https://api.专属域名.com`；如果确定API很简单，不会有进一步扩展，可以考虑放在主域名下，如`https://专属域名.com/api/`
- 路径：路径是一种地址，在互联网上表现为网址，在RESTful架构中，每个网址代表一种资源（resource），所以网址中不能有动词，只能有名词，而且所用的名词往往与数据库的表格名对应
- HTTP动词：
  - GET（SELECT）：从服务器取出资源（一项或多项）
  - POST（CREATE）：在服务器新建一个资源
  - PUT（UPDATE）：在服务器更新资源（客户端提供改变后的完整资源）
  - PATCH（UPDATE）：在服务器更新资源（客户端提供改变的属性）
  - DELETE（DELETE）：从服务器删除资源
  - HEAD：获取资源的元数据
  - OPTIONS：获取信息，关于资源的哪些属性是客户端可以改变的

## API参数

```go
package main

import (
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.GET("/user/:name/*action", func(c *gin.Context) {
        name := c.Param("name")
        action := c.Param("action")
        //截取/
        action = strings.Trim(action, "/")
        c.String(http.StatusOK, name+" is "+action)
    })
    //默认为监听8080端口
    r.Run(":8000")
}
```

## URL参数

- URL参数可以通过DefaultQuery()或Query()方法获取
- DefaultQuery()若参数不村则，返回默认值，Query()若不存在，返回空串
- API ? name=zs

```go
package main

import (
    "fmt"
    "net/http"

    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.GET("/user", func(c *gin.Context) {
        //指定默认值
        //http://localhost:8080/user 才会打印出来默认的值
        name := c.DefaultQuery("name", "我是默认值")
        c.String(http.StatusOK, fmt.Sprintf("hello %s", name))
    })
    r.Run(":8848")
}
```

## 表单参数

- `action`常见四种格式

  - ```html
    application/json
    application/x-www-form-urlencoded
    application/xml
    multipart/form-data
    ```

- 表单参数可以通过PostForm()方法获取，该方法默认解析的是x-www-form-urlencoded或from-data格式的参数

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Document</title>
</head>
<body>
    <form action="http://localhost:8848/form" method="post" action="application/x-www-form-urlencoded">
        用户名：<input type="text" name="username" placeholder="请输入你的用户名">  <br>
        密&nbsp;&nbsp;&nbsp;码：<input type="password" name="password" placeholder="请输入你的密码">  <br>
        <input type="submit" value="提交">
    </form>
</body>
</html>
```

```go
package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	r := gin.Default()
	r.POST("/form", func(c *gin.Context) {
		// 默认键值对
		types := c.DefaultPostForm("type", "post")
		username := c.PostForm("username")
		password := c.PostForm("password")

		c.String(http.StatusOK, fmt.Sprintf("username:%s,password:%s,type:%s", username, password, types))
	})
	r.Run(":8848")
}

```

## 上传单个文件

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Document</title>
</head>
<body>
    <form action="http://localhost:8080/upload" method="post" enctype="multipart/form-data">
          上传文件:<input type="file" name="file" >
          <input type="submit" value="提交">
    </form>
</body>
</html>
```

```go
package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	r := gin.Default()
	// 限制上传最大尺寸
	r.MaxMultipartMemory = 8 << 20
	r.POST("/upload", func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			c.String(http.StatusInternalServerError, "上传图片出错")
		}
		c.SaveUploadedFile(file, file.Filename)
		c.String(http.StatusOK, file.Filename, "\n")
		c.String(http.StatusOK, string(file.Size), "\n")
		for _, value := range file.Header {
			c.String(http.StatusOK, ":", value, "              ")
		}
	})
	r.Run(":8848")
}

```

## 上传特定文件

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.POST("/upload", func(c *gin.Context) {
        _, headers, err := c.Request.FormFile("file")
        if err != nil {
            log.Printf("Error when try to get file: %v", err)
        }
        //headers.Size 获取文件大小
        if headers.Size > 1024*1024*2 {
            fmt.Println("文件太大了")
            return
        }
        //headers.Header.Get("Content-Type")获取上传文件的类型
        if headers.Header.Get("Content-Type") != "image/png" {
            fmt.Println("只允许上传png图片")
            return
        }
        c.SaveUploadedFile(headers, "./video/"+headers.Filename)
        c.String(http.StatusOK, headers.Filename)
    })
    r.Run()
}
```

## 上传多个文件

```go
package main

import (
   "github.com/gin-gonic/gin"
   "net/http"
   "fmt"
)

// gin的helloWorld

func main() {
   // 1.创建路由
   // 默认使用了2个中间件Logger(), Recovery()
   r := gin.Default()
   // 限制表单上传大小 8MB，默认为32MB
   r.MaxMultipartMemory = 8 << 20
   r.POST("/upload", func(c *gin.Context) {
      form, err := c.MultipartForm()
      if err != nil {
         c.String(http.StatusBadRequest, fmt.Sprintf("get err %s", err.Error()))
      }
      // 获取所有图片
      files := form.File["files"]
      // 遍历所有图片
      for _, file := range files {
         // 逐个存
         if err := c.SaveUploadedFile(file, file.Filename); err != nil {
            c.String(http.StatusBadRequest, fmt.Sprintf("upload err %s", err.Error()))
            return
         }
      }
      c.String(200, fmt.Sprintf("upload ok %d files", len(files)))
   })
   r.Run(":8848")
}
```

## routes group

- 为了管理一些相同的API

```go
package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	v1 := r.Group("/v1")
	{
		v1.GET("/login", login)
		v1.GET("/submit", submit)
	}
	v2 := r.Group("/v2")
	{
		v2.GET("/login", login)
		v1.GET("/submit", submit)
	}
	r.Run("/8848")
}

func login(c *gin.Context) {
	name := c.DefaultQuery("name", "jack")
	c.String(200, fmt.Sprint("hello %s\n", name))
}
func submit(c *gin.Context)  {
	name := c.DefaultQuery("name","rose")
	c.String(200,fmt.Sprintf("hello %s\n", name))
}
```

## 路由拆分与注册

### 基本路由注册

```go
package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

func helloHandler(c *gin.Context)  {
	c.JSON(http.StatusOK, gin.H{
		"message":"hello world",
	})
}

func main() {
	r := gin.Default()
	r.GET("/test",helloHandler)
	if err:=r.Run(":8848");err!=nil{
		fmt.Println("start service failed,err:%v\n",err)
	}
}

```

### 路由拆分成单独的包

```go
// routers.go
package routers

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func helloHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "hello world",
	})
}
func SetupRouter() *gin.Engine {
	r := gin.Default()
	r.GET("/hello", helloHandler)
	return r
}
```

```go
package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"go_web/hello_world/routers"
	"net/http"
)

func helloHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "hello world",
	})
}

func main() {
	r := routers.SetupRouter()
	if err := r.Run(); err != nil {
		fmt.Println("start service failed, err:%v\n", err)
	}
}
```

# Gin数据解析和绑定

## Json数据解析和绑定

```go
package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

// 定义接受数据的结构体
type Login struct {
	// binding:"required"修饰的字段，若接收为空值，则报错，是必须的字段
	Username string `form:"username" json:"Username"  binding:"required"`
	Password string `form:"password" json:"Password"  binding:"required"`
}

func main() {
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"hint": "我是一个登录的API"})
	})
	r.POST("/", func(c *gin.Context) {
		// 声明接受的变量
		var json Login
		if err := c.ShouldBindJSON(&json); err != nil {
			// 返回错误信息
			// gin.H分装了生成json数据的工具
			c.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
		}
		if json.Username != "admin" || json.Password != "admin888" {
			c.JSON(http.StatusBadRequest, gin.H{"err": "Username or Password is error!"})
			return
		} else {
			c.JSON(http.StatusOK, gin.H{"flag": "flag{this_is_real_flag}"})
		}

	})
	r.Run(":8848")
}
```

## 表单数据解析和绑定

```html
<!--POST 表单-->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Document</title>
</head>
<body>
    <form action="http://localhost:8000/loginForm" method="post" enctype="application/x-www-form-urlencoded">
        用户名<input type="text" name="username"><br>
        密码<input type="password" name="password">
        <input type="submit" value="提交">
    </form>
</body>
</html>
```

```go
// go
package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

// 定义接受数据的结构体
type Login struct {
	// binding:"required"修饰的字段，若接收为空值，则报错，是必须的字段
	Username string `form:"username" binding:"required"`
	Password string `form:"password" binding:"required"`
}

func main() {
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"hint": "我是一个登录的API"})
	})
	r.POST("/", func(c *gin.Context) {
		// 声明接受的变量
		var form Login
		if err := c.Bind(&form); err != nil {
			
			c.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
		}
		if form.Username != "admin" || form.Password != "admin888" {
			c.JSON(http.StatusBadRequest, gin.H{"err": "Username or Password is error!"})
			return
		} else {
			c.JSON(http.StatusOK, gin.H{"flag": "flag{this_is_real_flag}"})
		}

	})
	r.Run(":8848")
}
```

## URI数据解析和绑定

```go
package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

// 定义接受数据的结构体
type Login struct {
	// binding:"required"修饰的字段，若接收为空值，则报错，是必须的字段
	Username string `uri:"username" binding:"required"`
	Password string `uri:"password" binding:"required"`
}

func main() {
	r := gin.Default()
	r.GET("/:username/:password", func(c *gin.Context) {
		var login Login
		if err := c.ShouldBindUri(&login);err != nil{
			c.JSON(http.StatusBadRequest,gin.H{"err":err.Error()})
		}
		if login.Username != "root" || login.Password != "admin"{
			c.JSON(http.StatusBadRequest,gin.H{"err":"账号或密码错误"})
		}else {
			c.JSON(http.StatusOK,gin.H{"success":"登录成功"})
		}
	})
	
	r.Run(":8848")
}

```

# Gin渲染

## 各种数据格式的响应

- Gin可以接受 json、结构体、XML、YAML等数据格式

```go
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/testdata/protoexample"
	"net/http"
)

type msg struct {
	Name    string
	Message string
	Number  int
}

// 定义接受数据的结构体
type Login struct {
	// binding:"required"修饰的字段，若接收为空值，则报错，是必须的字段
	Username string `uri:"username" binding:"required"`
	Password string `uri:"password" binding:"required"`
}

func main() {
	r := gin.Default()
	// json格式传递数据
	r.GET("/someJSON", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "this is a json"})
	})
	// 传递结构体数据
	r.GET("/someStruct", func(c *gin.Context) {
		res := msg{"root", "this_is_a_message", 123}
		c.JSON(200, res)
	})
	// 传递XML数据
	r.GET("/someXML", func(c *gin.Context) {
		c.XML(http.StatusOK, gin.H{"message": "this is a XML"})
	})
	// 传递YAML数据
	r.GET("/someYAML", func(c *gin.Context) {
		c.YAML(http.StatusOK, gin.H{"message": "this is a YAML"})
	})
	// protobuf格式,谷歌开发的高效存储读取的工具
	r.GET("/someProtoBuf", func(c *gin.Context) {
		reps := []int64{int64(1), int64(2)}
		label := "label"
		data := &protoexample.Test{
			Label: &label,
			Reps:  reps,
		}
		c.ProtoBuf(http.StatusOK, data)
	})

	r.Run(":8848")
}
```

## HTML模板渲染

- gin支持加载HTML模板，然后根据模板参数进行配置并返回相应的数据，本质上就是字符串替换
- `LoadHTMLGlob()`方法可以加载模板文件

- 类似于jsp，gin一般HTML后缀名为`*.tmpl`

当目录结构如下时：

![image-20220429204741192](https://husins.oss-cn-beijing.aliyuncs.com/image-20220429204741192.png)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>{{.title}}</title>
</head>
<body>
 ce is {{.ce}}
</body>
</html>
```

```go
package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	r := gin.Default()
	r.LoadHTMLGlob("template/*")
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{"title": "Test", "ce": "this is a test"})
	})
	r.Run(":8848")
}
```

## 模板语法



## 重定向

```go
package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "http://www.baidu.com")
	})
	r.Run(":8848")
}
```

## 同步和异步

```go
package main

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	// 1.创建路由
	// 默认使用了2个中间件Logger(), Recovery()
	r := gin.Default()
	// 1.异步
	r.GET("/long_async", func(c *gin.Context) {
		// 需要搞一个副本
		copyContext := c.Copy()
		// 异步处理
		go func() {
			time.Sleep(3 * time.Second)
			log.Println("异步执行：" + copyContext.Request.URL.Path)
		}()
	})
	// 2.同步
	r.GET("/long_sync", func(c *gin.Context) {
		time.Sleep(3 * time.Second)
		log.Println("同步执行：" + c.Request.URL.Path)
	})

	r.Run(":8848")
}
```

# gin中间件

## 全局中间件

- 当使用中间件，会优先执行中间件的代码，然后在执行路由的代码

```go
package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

func MiddleWare() gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()
		fmt.Println("中间件开始执行了")
		// 设置变量到Context的key中，可以通过Get（）取用
		c.Set("request", "中间件")
		status := c.Writer.Status()
		fmt.Println("中间件执行完毕", status)
		t2 := time.Since(t)
		fmt.Println("time", t2)
	}
}
func main() {
	// 1.创建路由
	// 默认使用了2个中间件Logger(), Recovery()
	r := gin.Default()
	// 注册中间件
	r.Use(MiddleWare())
	{
		r.GET("/test", func(c *gin.Context) {
			req, _ := c.Get("request")
			c.JSON(http.StatusOK, gin.H{"req": req})
		})
	}
	r.Run(":8848")
}
```

## Next方法

- 为解决中间件总是先于路由代码执行的问题，位于Next方法之后的代码，总是在路由代码运行之后执行

```go
package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

func MiddleWare() gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()
		fmt.Println("中间件开始执行了")
		// 设置变量到Context的key中，可以通过Get（）取用
		c.Set("request", "中间件")
		status := c.Writer.Status()
		c.Next()
		fmt.Println("中间件执行完毕", status)
		t2 := time.Since(t)
		fmt.Println("time", t2)
	}
}
func main() {
	// 1.创建路由
	// 默认使用了2个中间件Logger(), Recovery()
	r := gin.Default()
	// 注册中间件
	r.Use(MiddleWare())
	{
		r.GET("/test", func(c *gin.Context) {
			req, _ := c.Get("request")
			fmt.Println("request:", req)
			c.JSON(http.StatusOK, gin.H{"req": req})
		})
	}
	r.Run(":8848")
}

```

## 局部中间件

```go
package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

func MiddleWare() gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()
		fmt.Println("中间件开始执行了")
		// 设置变量到Context的key中，可以通过Get（）取用
		c.Set("request", "中间件")
		status := c.Writer.Status()
		c.Next()
		fmt.Println("中间件执行完毕", status)
		t2 := time.Since(t)
		fmt.Println("time", t2)
	}
}
func main() {
	// 1.创建路由
	// 默认使用了2个中间件Logger(), Recovery()
	r := gin.Default()
	{
		r.GET("/test",MiddleWare(),func(c *gin.Context) {
			req, _ := c.Get("request")
			fmt.Println("request:", req)
			c.JSON(http.StatusOK, gin.H{"req": req})
		})
	}
	r.Run(":8848")
}
```

# 会话控制

## Cookie使用

```go
package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
)

func main() {
	// 1.创建路由
	// 默认使用了2个中间件Logger(), Recovery()
	r := gin.Default()
	// 服务端要给客户端cookie
	r.GET("cookie", func(c *gin.Context) {
		// 获取客户端是否携带cookie
		cookie, err := c.Cookie("key_cookie")
		if err != nil {
			cookie = "NotSet"
			// 给客户端设置cookie
			//  maxAge int, 单位为秒，过期时间
			// path,cookie所在目录
			// domain string,域名
			//   secure 是否智能通过https访问
			// httpOnly bool  是否允许别人通过js获取自己的cookie
			c.SetCookie("key_cookie", "value_cookie", 60, "/",
				"localhost", false, true)
		}
		fmt.Printf("cookie的值是： %s\n", cookie)
	})
	r.Run(":8848")
}

```

## Cookie练习

- 模拟实现权限验证中间件
  - 有2个路由，login和home
  - login用于设置cookie
  - home是访问查看信息的请求
  - 在请求home之前，先跑中间件代码，检验是否存在cookie
- 访问home，会显示错误，因为权限校验未通过

```go
package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func AuthMiddleWare() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取客户端cookie并校验
		if cookie, err := c.Cookie("abc"); err == nil {
			if cookie == "123" {
				c.Next()
				return
			}
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"err": "验证不通过"})
			c.Abort()
			return
		}

	}
}

func main() {
	// 1.创建路由
	// 默认使用了2个中间件Logger(), Recovery()
	r := gin.Default()
	r.GET("/login", func(c *gin.Context) {
		c.SetCookie("abc", "123", 3600, "/", "127.0.0.1", false, true)
		c.String(http.StatusOK, "Login success!")
	})
	r.GET("/home", AuthMiddleWare(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"data": "admin"})
	})
	r.Run(":8848")
}

```

## Session

```go
package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"net/http"
)

var store = sessions.NewCookieStore([]byte("something-very-secret"))

func SaveSession(c *gin.Context) {
	session, err := store.Get(c.Request, "username")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"401": "没有权限访问"})
		return
	}
	session.Values["foo"] = "bar"
	session.Values[42] = 43
	session.Save(c.Request, c.Writer)
}

func GetSession(c *gin.Context) {
	session, err := store.Get(c.Request, "username")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"401": "没有权限访问"})
		return
	}
	foo := session.Values["foo"]
	fmt.Println(foo)
}
func main() {
	// 1.创建路由
	// 默认使用了2个中间件Logger(), Recovery()
	r := gin.Default()
	r.GET("/save", SaveSession)
	r.GET("/get", GetSession)
	r.Run(":8848")
}
```





































































































