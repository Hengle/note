<!-- TOC -->

- [1. 解决Chromium “缺少 Google API 密钥”问题](#1-解决chromium-缺少-google-api-密钥问题)
    - [1.1. 解决方法一：屏蔽提示（不需要登录Google）](#11-解决方法一屏蔽提示不需要登录google)
    - [1.2. 解决方法二：使用公开KEY（登录公开Google）](#12-解决方法二使用公开key登录公开google)
    - [1.3. 解决方法三：使用自己的KEY（登录自己的Google）](#13-解决方法三使用自己的key登录自己的google)

<!-- /TOC -->
# 1. 解决Chromium “缺少 Google API 密钥”问题
每次打开Chromium，地址栏下方就会提示“缺少Google API密钥，因此Chromium的部分功能将无法使用”。
## 1.1. 解决方法一：屏蔽提示（不需要登录Google）
设置环境变量，打开windows的cmd命令提示符，依次输入以下命令：
```cmd
setx GOOGLE_API_KEY "no"
setx GOOGLE_DEFAULT_CLIENT_ID "no"
setx GOOGLE_DEFAULT_CLIENT_SECRET "no"
```
可能需要重启电脑。
## 1.2. 解决方法二：使用公开KEY（登录公开Google）
cmd 命令提示符，依次输入以下命令：
```cmd
setx GOOGLE_API_KEY AIzaSyDCNWofwOkYgeS3aBnd901sIJqSS4p3nKc
setx GOOGLE_DEFAULT_CLIENT_ID 752805503192-gigd4quq46757vjupq4rv5oga3sougnp.apps.googleusercontent.com
setx GOOGLE_DEFAULT_CLIENT_SECRET bEbljK3NYvuRBe-zn7UyS4Zy
```
可能需要重启电脑。
## 1.3. 解决方法三：使用自己的KEY（登录自己的Google）
* https://cloud.google.com/console
* 创建或选择已有项目 → 左侧边栏 API和服务 → 凭证
* 创建凭证(类型为 “API 密钥”,名称随意, 不使用密钥限制,记住生成的key)
* 再创建一个凭证(类型为 “OAuth 客户端 ID”, 名称随意, 应用类型选择 “其他”, 记住生成的 “客户端 ID” 和 “客户端密钥”)
* 格式填写自己的 API Key
```cmd
setx GOOGLE_API_KEY 生成的API密钥
setx GOOGLE_DEFAULT_CLIENT_ID 生成的客户端ID
setx GOOGLE_DEFAULT_CLIENT_SECRET 生成的客户端密钥
```
可能需要重启电脑。