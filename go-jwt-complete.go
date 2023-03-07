package main

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

//全局的数据，相当于配置参数，数据等
type User struct { //定义一个用户结构体,将数据bind到这个结构体上
	Username string `form:"username" json:"username"`
	Password string `form:"password" json:"password"`
}

var dataDB = map[string]string{
	"zty":  "123456",
	"zty1": "654321",
}                    //定义一个map，用来存储用户信息
type Claims struct { //将不重要的username放入荷载中，同时还要带上标准的jwt，相当于是申明模板
	Username string `json:"username"`
	jwt.StandardClaims
}

var jwtKey = []byte("zty-go-jwt") //设置你的签名,全局签名，这个签名需要加密
//使用JWT完成用户认证

//整个网站入口
func main() {

	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		c.String(200, "go-jwt实现")
	})

	router.POST("/signin", Signin)
	router.POST("/welcome", Welcome)
	router.POST("/refresh", RefreshToken)
	router.Run()

}

//用户登录函数，实现用户名和密码的验证随后颁发令牌
func Signin(c *gin.Context) {
	var user User

	if err := c.ShouldBind(&user); err != nil { //输入的数据绑定到结构体上，这里的绑定要求传过来的参数和结构体中的参数名相同，这样就可以直接绑定
		c.JSON(400, gin.H{"error": err.Error()}) //失败返回400
		return
	}
	//通过用户名拿到密码，一般这里要查数据库，这里方面就用map来模拟
	password, ok := dataDB[user.Username]
	if !ok || password != user.Password { //如果没有查到用户名即ok为false，或者密码不正确，则返回错误
		c.JSON(400, gin.H{"error": "用户名或密码错误"})
		return
	}

	//现在是密码正确，验证通过的情况，我们现在要来生成token了
	//首先设置我们的过期时间，这个必须的
	expireTime := time.Now().Add(10 * time.Minute) //设置过期时间为3小时
	//然后设置颁发者，这个可以不必须
	issuer := "zty-test"
	//创建JWT申明，并加入们的用户名
	claims := &Claims{ //按照设计好的申明类型来进行创建,现在claim是一个指针
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expireTime.Unix(), //过期时间
			Issuer:    issuer,            //颁发者
		},
	}

	//生成token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) //加入你要使用的加密算法,和你选择放入的claims（这里可携带的信息是服务器定的，之后你客户端给我返回的应该也是同样的信息）
	//这里会自动生成JWT头部，载荷。
	tokenString, err := token.SignedString(jwtKey) //我服务器的私钥进行签名，生成最终的JWT字符串
	if err != nil {
		c.JSON(500, gin.H{"error": "生成token失败"})
		return
	}

	//设置客户端的cookie token设置为刚刚生成的token
	c.SetCookie("token", tokenString, 3600, "/", "localhost", false, true) //设置cookie
	c.JSON(200, gin.H{                                                     //返回token
		"token": tokenString,
	})

}

//身份验证
func Welcome(c *gin.Context) {
	//获取客户端的cookie

	tokenString, err := c.Cookie("token")
	//从cookie中获取token
	if err != nil {
		//如果没有设置cookie，则返回未授权状态码
		if err == http.ErrNoCookie {
			c.JSON(401, gin.H{"error": "未授权1"})
			return
		}
		//其他错误
		c.JSON(400, gin.H{
			"error": "获取token失败1",
			"err":   err.Error(),
		})
		return
	}
	claims := &Claims{}
	//解析token
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		//这里的token是客户端传过来的token，claims是你自己定义的结构体，这里的func是用来验证token的
		//这个func是密钥函数，它会根据你JWT的头部中的alg字段来判断你使用的是哪种加密算法，然后再根据你的密钥来生成tok
		return jwtKey, nil
	})

	if err != nil {
		//如果解析失败，说明token无效
		if err == jwt.ErrSignatureInvalid {
			c.JSON(401, gin.H{
				"error": "未授权2",
				"err":   err.Error(),
			})
			return
		}
		c.JSON(400, gin.H{
			"error": "解析token失败，令牌错误或已过期",
			"err":   err.Error(),
		}) //过期同样也会解析失败
		return
	}
	//验证token
	if claims, ok := token.Claims.(*Claims); ok && token.Valid { //验证token
		c.JSON(200, gin.H{
			"username": claims.Username,
			"expireAt": time.Unix(claims.ExpiresAt, 0).Format("2006-01-02 15:04:05"),
		})
	} else {
		c.JSON(400, gin.H{"error": "token无效"})
		return
	}
}

//用来刷新令牌的函数
func RefreshToken(c *gin.Context) {
	//续签令牌

	//获取客户端的cookie
	tokenString, err := c.Cookie("token") //从cookie中获取token
	if err != nil {
		//如果没有设置cookie，则返回未授权状态码
		if err == http.ErrNoCookie {
			c.JSON(401, gin.H{
				"error": "未授权",
				"err":   err.Error(),
			})
			return
		}
		//其他错误
		c.JSON(400, gin.H{
			"error": "获取token失败",
			"err":   err.Error(),
		})
		return
	}

	claims := &Claims{}
	//解析token
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) { //这里的token是客户端传过来的token，claims是你自己定义的结构体，这里的func是用来验证token的，
		//这个func是密钥函数，它会根据你JWT的头部中的alg字段来判断你使用的是哪种加密算法，然后再根据你的密钥来生成tok
		return jwtKey, nil
	})

	if err != nil {
		//如果解析失败，说明token无效
		if err == jwt.ErrSignatureInvalid {
			c.JSON(401, gin.H{
				"error": "未授权2",
				"err":   err.Error(),
			})
			return
		}
		c.JSON(400, gin.H{"error": "解析token失败，令牌错误或已过期"})
		return
	}

	if !token.Valid {
		c.JSON(400, gin.H{"error": "token无效"})
		return
	}

	//这个方法是要用来刷新令牌，首先我们要判断令牌是否即将到期，假如令牌时间还很长，我们则返回错误，否则刷新其令牌
	//获取token中的过期时间

	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 10*time.Minute { //如果token的过期时间减去当前时间大于30秒，则返回错误
		c.JSON(400, gin.H{
			"err": "令牌时间未到",
		})
		return
	}

	//创建新的令牌并为其延长时间
	expirationTime := time.Now().Add(10 * time.Hour)
	claims.ExpiresAt = expirationTime.Unix()

	newtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	newtokenString, err := newtoken.SignedString(jwtKey)

	if err != nil {
		c.JSON(500, gin.H{
			"error": "生成token失败",
			"err":   err.Error(),
		})
		return
	}

	//返回新的token
	c.SetCookie("token", newtokenString, 3600, "/", "localhost", false, true) //设置cookie
	c.JSON(200, gin.H{                                                        //返回token
		"token": newtokenString,
	})

}
