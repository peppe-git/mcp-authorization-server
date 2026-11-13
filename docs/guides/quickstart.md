# Put OAuth in front of your MCP server in 10 minutes

You have a Spring Boot 4.1 application that serves MCP on `/mcp`, through the MCP Java SDK, Spring AI
MCP or your own controller. At the end of this guide:

- MCP clients discover your authorization server from a 401;
- the user signs in with your application's login and approves the client;
- every MCP request carries a token checked in-process.

## 1. Add the starter (1 minute)

Use the latest released version (until the first release, build it locally with `./mvnw install`):

```xml
<dependency>
    <groupId>io.github.peppe-git</groupId>
    <artifactId>mcp-authorization-server-spring-boot-starter</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Your application also needs `spring-boot-starter-webmvc` and `spring-boot-starter-security`. It most
likely has them already.

## 2. Configure issuer, resource and scopes (2 minutes)

```yaml
mcp:
  authorization-server:
    issuer: https://mcp.example.com          # the public origin of this application
    resource: https://mcp.example.com/mcp    # the public URL of the MCP endpoint
    resource-name: Example MCP server
    scopes:
      - name: tools.read
        description: See your projects
        default-scope: true
      - name: tools.write
        description: Create and change projects
    resource-server:
      path-patterns: [/mcp, /mcp/**]         # the default
```

`issuer` and `resource` must be the URLs clients see. Behind a reverse proxy, use the public HTTPS
origin, not the internal address. `http` is accepted only for `localhost`.

## 3. Let users sign in (2 minutes)

The consent page needs a signed-in user. The starter uses whatever login your application already has:
form login, OAuth login or SSO. The only requirement is a session-based `SecurityContext`.

- **No security configuration of your own:** the starter adds a fallback chain with form login for
  every other route.
- **A chain of your own:** keep it. The starter's chains have higher precedence and cover only
  `/oauth2/*`, `/.well-known/*` and the MCP path.
- **A login page that is not at `/login`:** set `mcp.authorization-server.login-page`.

Tell the starter who the user is, and whether they are still allowed in:

```java
@Bean
McpPrincipalResolver principals(UserRepository users) {
    return new McpPrincipalResolver() {
        @Override
        public Optional<McpPrincipal> resolve(Authentication auth) {
            return users.findByLogin(auth.getName())
                .map(u -> new McpPrincipal(u.id().toString(), u.displayName()));
        }

        @Override
        public boolean isActive(String subject) {   // called on every MCP request and refresh
            return users.findById(UUID.fromString(subject)).filter(User::enabled).isPresent();
        }
    };
}
```

## 4. Read the caller in your MCP code (1 minute)

The MCP request is authenticated as a `BearerTokenAuthentication`:

```java
var auth = (BearerTokenAuthentication) SecurityContextHolder.getContext().getAuthentication();
String subject = auth.getName();                               // McpPrincipal.subject()
boolean canWrite = auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_tools.write"));
```

## 5. Store grants in your database (2 minutes, before production)

The default store is in memory: single instance only, and grants are lost on restart. For production:

1. Apply `classpath:io/github/peppe_git/mcpauthserver/store/schema-postgresql.sql` with your
   migration tool.
2. Set:

```yaml
mcp:
  authorization-server:
    store: jdbc
```

## 6. Try it (2 minutes)

Run the sample, then go through the steps below:

```bash
./mvnw -pl samples/sample-mcp-server -am spring-boot:run
```

1. Discovery:

   ```bash
   curl -i -X POST localhost:8080/mcp
   ```

   The 401 carries `resource_metadata`.

2. Open this URL in a browser and sign in as `demo` / `demo`:

   `http://localhost:8080/oauth2/authorize?response_type=code&client_id=sample-cli&redirect_uri=http://127.0.0.1:8765/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=x`

3. Approve. The browser goes to `127.0.0.1:8765/callback?code=…` (nothing listens there; copy the code
   from the address bar).

4. Exchange the code:

   ```bash
   curl -s localhost:8080/oauth2/token -d grant_type=authorization_code -d client_id=sample-cli -d redirect_uri=http://127.0.0.1:8765/callback -d code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk -d code=PASTE_CODE
   ```

5. Call MCP with the access token:

   ```bash
   curl -s localhost:8080/mcp -H "Authorization: Bearer PASTE_ACCESS_TOKEN" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
   ```

With a real MCP client, add `http://localhost:8080/mcp` as a remote server. Clients that support
Client ID Metadata Documents need no registration. Clients that only support dynamic registration need
`mcp.authorization-server.dcr.enabled=true`, and a rate limit in front of `/oauth2/register`.

## Before production

- Use HTTPS end to end, with a public `issuer`.
- Use `store: jdbc` when you run more than one instance.
- Rate-limit `/oauth2/authorize`, `/oauth2/token` and, if enabled, `/oauth2/register`. The starter does
  not, because the right key (IP, proxy header) depends on your network.
- Implement `McpPrincipalResolver.isActive`.
- Listen to `McpAuthorizationEvent` and keep an audit trail; alert on `RefreshTokenReuseDetected`.
- Read [what is not guaranteed](../../README.md#what-is-not-guaranteed).
