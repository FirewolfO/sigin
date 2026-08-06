# Sign-in Service

云服务统一身份认证后端。服务提供账号注册、登录、退出、会话恢复、个人资料和用户 API AK/SK 管理。账号使用密码登录；已绑定的邮箱或手机号使用一次性验证码登录。

## 技术栈

- Java 21、Spring Boot 3.5
- Spring Security Cookie Session、Cookie CSRF
- Spring Data JPA、Flyway、H2 文件数据库
- Maven Wrapper

## 本地启动

准备 JDK 21 和必要密钥后执行：

```bash
export SIGNIN_CREDENTIAL_ENCRYPTION_KEY='replace-with-a-stable-random-master-key'
export SIGNIN_INNER_GATEWAY_ACCESS_KEY='gwak_...'
export SIGNIN_INNER_GATEWAY_SECRET_KEY='gwsk_...'
./mvnw spring-boot:run
```

服务固定默认监听 `http://localhost:8084`，数据库默认保存到 `./data/signin.mv.db`。常用配置见 [.env.example](.env.example)。

浏览器只在注册、登录和验证码流程中直接请求本服务，并在写请求前调用 `GET /api/v1/auth/csrf`。登录后的用户、退出、资料、密码和 API 密钥请求由 `cloud-ui` 统一发往 Gateway 的 `/api/open/signin/**`，不再直连本服务。

本地联调验证码登录时显式设置 `SIGNIN_VERIFICATION_CODE_EXPOSE=true`，发送接口会在 `developmentCode` 字段返回测试验证码。该开关不得用于生产环境，也不得记录验证码。生产环境应配置：

```bash
SIGNIN_VERIFICATION_CODE_EXPOSE=false
SIGNIN_VERIFICATION_CODE_WEBHOOK=https://notification.internal/v1/verification-codes
SIGNIN_VERIFICATION_CODE_TOKEN=replace-with-secret-token
```

Webhook 接收 `POST` JSON 请求，字段为 `channel`（`EMAIL` 或 `PHONE`）、`destination`、`code`、`purpose`（固定为 `LOGIN`）和 `expiresInSeconds`；配置 Token 后请求携带 `Authorization: Bearer ...`。连接超时为 3 秒，读取超时为 5 秒。

## 接口

| 方法 | 路径 | 登录要求 | 用途 |
| --- | --- | --- | --- |
| `GET` | `/api/v1/auth/csrf` | 否 | 初始化 CSRF Cookie |
| `POST` | `/api/v1/auth/register` | 否 | 注册并建立登录会话 |
| `POST` | `/api/v1/auth/login` | 否 | 账号密码登录 |
| `POST` | `/api/v1/auth/verification-codes` | 否 | 向已绑定邮箱或手机号发送登录验证码 |
| `POST` | `/api/v1/auth/code-login` | 否 | 邮箱或手机号验证码登录 |
| `GET` | `/api/v1/auth/me` | 是 | 获取当前用户 |
| `POST` | `/api/v1/auth/logout` | 是 | 注销并使 Session 失效 |
| `PUT` | `/api/v1/account/profile` | 是 | 修改显示名称、邮箱、手机号和头像 |
| `PUT` | `/api/v1/account/password` | 是 | 校验当前密码后修改登录密码 |
| `GET/POST` | `/api/v1/account/api-credentials` | 是 | 查询或创建用户 API AK/SK |
| `POST` | `/api/v1/account/api-credentials/{id}/secret` | 是 | 按需读取当前账号的一条 SK，用于显式复制 |
| `DELETE` | `/api/v1/account/api-credentials/{id}` | 是 | 删除用户 API AK/SK |
| `POST` | `/api/v1/inner/credentials/resolve` | Gateway HMAC | 解析有效的用户 AK/SK，具体 OpenAPI 是否允许编程访问由 Gateway 路由配置决定 |
| `POST` | `/api/v1/inner/credentials/exchange` | Gateway HMAC + Session | 将登录态换成短期 AK/SK |
| `GET` | `/actuator/health` | 否 | 健康检查 |

完整契约见 [openapi.yaml](src/main/resources/static/openapi.yaml)，服务启动后也可通过 `GET /openapi.yaml` 获取。

验证码为安全随机生成的 6 位数字，仅以 BCrypt 摘要存储在 `login_verification_codes` 表中。验证码 5 分钟过期、60 秒内不可重发、每小时最多发送 5 次、最多尝试 5 次，并在成功登录后立即失效。

用户 SK 和登录态交换得到的短期 STS SK 都使用 `SIGNIN_CREDENTIAL_ENCRYPTION_KEY` 经 AES-GCM 加密入库。Gateway 先通过已注册的 `/api/inner/signin/credentials/exchange` 把 `CLOUD_SESSION` 换成 STS，再用 STS 对实际上游路径重新签名；本服务验签后仅为当前请求恢复用户身份。Gateway 调用 Inner 接口使用 `SIGNIN_INNER_GATEWAY_ACCESS_KEY` 和 `SIGNIN_INNER_GATEWAY_SECRET_KEY`；这组值必须与 Gateway 的调用配置一致。

## 验证

```bash
./mvnw test
```
