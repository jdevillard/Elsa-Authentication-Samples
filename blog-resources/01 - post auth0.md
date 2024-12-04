# Configure Authentication in Elsa Workflows Environment

## Introduction

Elsa Workflows is a powerful and flexible execution engine, encapsulated as a set of open-source .NET libraries designed to infuse .NET applications with workflow capabilities. With Elsa, developers can weave logic directly into their systems, enhancing functionality and automation and align seamlessly with the application’s core functionality.

Visit the [ELSA documentation](https://elsa-workflows.github.io/elsa-documentation) website for more information.

As a maintener on this solution, I see a lot of people that need some help about configuring authentication in Elsa Server + Dashboard.

The purpose of this blog post is to explain step by step different type of authentication configuration for Elsa

## How to begin

First of all, we'll start a new project from scratch and take a look at the simple user/password authentication available by default in the solution.

### Prepare the project - basic username/password

For this we'll use the documentation available at https://elsa-workflows.github.io/elsa-documentation/elsa-server-studio.html#setup-host that consist in create a Host server and a studio wasm application

You can find the sample project at 01-BasicAuth

In this sample, we use on the Host : 

```csharp
        .UseIdentity(identity =>
        {
            identity.TokenOptions = options => options.SigningKey = "large-signing-key-for-signing-JWT-tokens";
            identity.UseAdminUserProvider();
        })
        .UseDefaultAuthentication()
```

The purpose of `UseIdentity()` is to defined the services and interfaces  for the JWT Token generation and the differents providers/store to retrieve users and roles. (By default all stores are in memory). At this point, if you need to use your custom User/Role schema configuration, you can override the providers with yours.

By default, only 1 user (admin:password) is available and map to the admin role.

The purpose of `UseDefaultAuthentication` is used to add a Jwt or ApiKey authentication and authorization mecanism on the Host.


I see a lot of issue/questions on GitHub asking for how to configure OpenId or any Authentication Provider SaaS , custom etc...

We will see next what we need to do to configure all of this. But before , let's recap some terminology and component in Authentication/Authorization (AuthN/AuthZ).

I used to work with IdentityServer in DotNet for a while and you can find a lot of explanation on the site of [Duende Software](https://docs.duendesoftware.com/identityserver/v7/overview/terminology/) which is the former IdentityServer Team.

So you will have to identify : 
- The user : the user that make a call
- The Clients : the software or component that make the call (Desktop, mobile, etc..)
- The Resources : the Api you call
- The Authentication Server : responsible of delivering Token
- The Authorization Server : responsible of validating Token

The last two server can be generaly mixed together.

In our case, we have the following in the case of the sample 01 (user/password):
- The user : the user that make a call
- The Clients : The Elsa Server Browser
- The Resources : The Elsa Server Api 
- The Authentication Server : The Elsa Server Host
- The Authorization Server : The Elsa Server Host

# Open Id Configuration

If we want to use a OpenID provider, the authentication server will be the OpenId Provider (eg, Auth0, Microsoft Entra Id).

Microsoft provide some standard libraries to authenticate a user using OpenId. 
The process is simple : 
- Challenge an authentication
  - redirect to Authentication Server
  - authenticate the user
  - redirect to the web site with a identity token containing the scope/claims etc...
  - then the different token are placed in a cookie and the Web Site is responsible of validating the cookie regarding information available inside.

So in our sample, we will need to know `when the user is authenticated/unauthenticated` and provide a `login/logout` process to challenge the authentication mechanism with the Authentication Server.

Then we can use the token provided by the authentication server in the cookie with information about role/permissions etc... In this case, the AuthN server is also an AuthZ server.
Or we can provide a new access token regarding information in a database for permissions about user, role etc... In this case, the WebSite (Elsa Studio Server) will be the Authorization Server. 

## Basic Configuration of any Open Id Provider

Microsoft provides the  [Microsoft.AspNetCore.Authentication.OpenIdConnect](https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.OpenIdConnect) package. 
Here is how we can configure it in the Program.cs

```csharp
// ...other code...

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        }).AddCookie()
        .AddOpenIdConnect("OpenId", options => {
            options.Authority = $"https://{Configuration["OpenIdProvider:Domain"]}";
    
            options.ClientId = Configuration["OpenIdProvider:ClientId"];
            options.ClientSecret = Configuration["OpenIdProvider:ClientSecret"];
    
            options.ResponseType = OpenIdConnectResponseType.Code;
    
            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.Scope.Add("email");
    
            options.CallbackPath = new PathString("/callback");
    
            options.ClaimsIssuer = Configuration["OpenIdProvider:Name"];
    
            options.SaveTokens = true;
    
            options.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "name"
            };
    
            options.Events = new OpenIdConnectEvents
            {
                OnRedirectToIdentityProviderForSignOut = (context) =>
                {
                    //Configure the Logout Uri of the OpenIdProvider
                    var logoutUri = ....
    
                    context.Response.Redirect(logoutUri);
                    context.HandleResponse();
    
                    return Task.CompletedTask;
                }
            };
        });
    
    }
```
To be able to enter the authentication process of OpenId, we need to challenge the authentication in case of unauthenticated user.
For this, we can defined 2 route `Account/Login` and `Account Logout` :

```csharp
public static IEndpointRouteBuilder UseLoginPage(this IEndpointRouteBuilder app)   
{

    app.MapGet("/Account/Login", async (HttpContext httpContext, string redirectUri = "/") =>
    {
        var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
                .WithRedirectUri(redirectUri)
                .Build();
                //challenge the OpenId Authentication Scheme
        await httpContext.ChallengeAsync("OpenId", authenticationProperties);
    });

    app.MapGet("/Account/Logout", async (HttpContext httpContext, string redirectUri = "/") =>
    {
        var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
                .WithRedirectUri(redirectUri)
                .Build();

        //Signout of OpenId and Cookie scheme
        await httpContext.SignOutAsync("OpenId", authenticationProperties);
        await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    });

    return app;
}
```

Using the Extensibility of the Elsa Studio, I've added a component that display a login/logout button in the App Bar of the studio.

[img]

When you click on the login button, you will be redirected to `/Account/Login` and the challenge will started.

[img]

Now let see how we can configure the authentication and authorization using Auth0.

## Use Auth0 

We can use Auth0 as a Authentication Server First.
If we follow the use of the Microsoft Package, we can follow this [Auth0 Blob Post](https://auth0.com/blog/using-csharp-extension-methods-for-auth0-authentication/)

```csharp
services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        }).AddCookie()
        .AddOpenIdConnect("Auth0", options => {
            options.Authority = $"https://{Configuration["Auth0:Domain"]}";
    
            options.ClientId = Configuration["Auth0:ClientId"];
            options.ClientSecret = Configuration["Auth0:ClientSecret"];
    
            options.ResponseType = OpenIdConnectResponseType.Code;
    
            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.Scope.Add("email");
    
            options.CallbackPath = new PathString("/callback");
    
            options.ClaimsIssuer = "Auth0";
    
            options.SaveTokens = true;
    
            options.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "name"
            };
    
            options.Events = new OpenIdConnectEvents
            {
                OnRedirectToIdentityProviderForSignOut = (context) =>
                {
                    var logoutUri = $"https://{Configuration["Auth0:Domain"]}/v2/logout?client_id={Configuration["Auth0:ClientId"]}";
    
                    var postLogoutUri = context.Properties.RedirectUri;
                    if (!string.IsNullOrEmpty(postLogoutUri))
                    {
                        if (postLogoutUri.StartsWith("/"))
                        {
                            var request = context.Request;
                            postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                        }
                        logoutUri += $"&returnTo={ Uri.EscapeDataString(postLogoutUri)}";
                    }
    
                    context.Response.Redirect(logoutUri);
                    context.HandleResponse();
    
                    return Task.CompletedTask;
                }
            };
        });
```


or we can use the [AspNet Core authentication SDK](https://auth0.com/blog/exploring-auth0-aspnet-core-authentication-sdk/) which simplify a lot of thing : 

```csharp
services.AddAuth0WebAppAuthentication(options =>
  {
    options.Domain = configuration["Auth0:Domain"];
    options.ClientId = configuration["Auth0:ClientId"];
  });
```

The code is as simple as possible ! 

with this first lines of configuration, you will be able to authenticate users.

Then we need to handle the OpenId Event `OnTicketReceived`, to intercept the return of the Authentication Server and add some customization on our access token before save it in the cookie : 

```csharp
options.OpenIdConnectEvents = new Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectEvents()
{
    OnTicketReceived = async (ctx) =>
    {
        using var scope = ctx.HttpContext.RequestServices.CreateAsyncScope();
        var jwtAccessor = scope.ServiceProvider.GetRequiredService<IJwtAccessor>();

        //Need to create a JWT Tokens to work with the Elsa Server.

        var claimsIdentity = (ClaimsIdentity?)ctx?.Principal?.Identity;

        var tokenIssuer = scope.ServiceProvider.GetRequiredService<IAccessTokenIssuer>();
        var jwtTokens = await tokenIssuer.IssueTokensAsync(claimsIdentity, ["*"], []);

        var newTokens = ctx.Properties.GetTokens()
            .ToList();
        //Add a new access token created by the studio in the cookie, this access token will be available for the call of the backend API
        newTokens.Add(new AuthenticationToken() { Name = "accessToken", Value = jwtTokens.AccessToken });
        ctx.Properties.StoreTokens(newTokens);
    }
};
```

With this code, we handle the return of the OpenId Provider with the Event `OnTicketReceived`

The idea is to create a new JWT Bearer using a JWT Token issuer. Why we want to do this ? Because, for now, we don't have change any of the authorization mechanism  on the Elsa Api Server Side. So the API is waiting for an JWT with the following properties 
- Audience : http://elsa.api
- Issuer : http://elsa.api
- SigningKey : define in parameter. (We use the same key to create the JWT Token)

In this token, we add the `*` to allow access to all resources. At this point, you can map information regarding the user connected and the roles/permissions you allow for him/her.

Once the Token is created, we embbed it in the cookie for further use in the process.

### Use the Acces Token

Now we have the cookie to authenticate us on the Portal and allow navigation, and we need to use the `Access Token` to call the BackEnd Api.

That is the purpose of the `AuthenticationHandler` defined in the Startup : 
```csharp
builder.Services.AddRemoteBackend((configureElsaClient) => configureElsaClient.AuthenticationHandler = typeof(AuthenticatingApiHttpMessageHandler),
        (backendOptions) => configuration.GetSection("Backend").Bind(backendOptions)

    );
```

The `AuthenticatingApiHttpMessageHandler` is used to retrieve the JWT Access Token using an IJwtAccessor and use it in the call to the Api.
For the purpose of the demonstration, I've redefine this class to facilitate debug but you can use the one provided by the Elsa Framework (You just have to be sure to implement correctly the Refresh Token Part, for now I've just defined the simple ReadToken)

```csharp
/// <summary>
/// An <see cref="HttpMessageHandler"/> that configures the outgoing HTTP request to use the access token as bearer token.
/// </summary>
public class AuthenticatingApiHttpMessageHandler(IRemoteBackendAccessor remoteBackendAccessor, IBlazorServiceAccessor blazorServiceAccessor)
    : DelegatingHandler
{
    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var sp = blazorServiceAccessor.Services;
        var jwtAccessor = sp.GetRequiredService<IJwtAccessor>();
        var accessToken = await jwtAccessor.ReadTokenAsync(TokenNames.AccessToken);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var response = await base.SendAsync(request, cancellationToken);

        //Implement Refresh Token
        /*
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            //// Refresh token and retry once.
            var tokens = await RefreshTokenAsync(jwtAccessor, cancellationToken);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

            // Retry.
            response = await base.SendAsync(request, cancellationToken);
        }
        */
        return response;
    }
}
``` 


Now you can create workflow and manipulate the Api Server from the Studio.

In further post, we'll see how to configure Auth0 access token for Server side (Auth0 will make the AuthZ).

All the code of this article is available at https://medium.com/r/?url=https%3A%2F%2Fgithub.com%2Fjdevillard%2FElsa-Authentication-Samples