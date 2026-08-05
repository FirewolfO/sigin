# Sign-in Service

云服务统一身份认证后端。服务提供账号注册、登录、退出、会话恢复和个人资料维护，支持使用账号、邮箱或手机号登录。

## 技术栈

- Java 21、Spring Boot 3.5
- Spring Security Cookie Session、Cookie CSRF
- Spring Data JPA、Flyway、H2 文件数据库
- Maven Wrapper

## 本地启动

准备 JDK 21 后执行：

```bash
./mvnw spring-boot:run
```

服务固定默认监听 `http://localhost:8084`，数据库默认保存到 `./data/signin.mv.db`。常用配置见 [.env.example](.env.example)。

浏览器调用写接口前，需要先请求 `GET /api/v1/auth/csrf`。服务会设置 `XSRF-TOKEN` Cookie；后续请求同时携带 Session Cookie，并将该值放入 `X-XSRF-TOKEN` 请求头。`cloud-ui` 的统一 API Client 已实现此流程。

## 接口

| 方法 | 路径 | 登录要求 | 用途 |
| --- | --- | --- | --- |
| `GET` | `/api/v1/auth/csrf` | 否 | 初始化 CSRF Cookie |
| `POST` | `/api/v1/auth/register` | 否 | 注册并建立登录会话 |
| `POST` | `/api/v1/auth/login` | 否 | 账号、邮箱或手机号登录 |
| `GET` | `/api/v1/auth/me` | 是 | 获取当前用户 |
| `POST` | `/api/v1/auth/logout` | 是 | 注销并使 Session 失效 |
| `PUT` | `/api/v1/account/profile` | 是 | 修改显示名称、邮箱、手机号和头像 |
| `GET` | `/actuator/health` | 否 | 健康检查 |

完整契约见 [openapi.yaml](src/main/resources/static/openapi.yaml)，服务启动后也可通过 `GET /openapi.yaml` 获取。

## 验证

```bash
./mvnw test
```
