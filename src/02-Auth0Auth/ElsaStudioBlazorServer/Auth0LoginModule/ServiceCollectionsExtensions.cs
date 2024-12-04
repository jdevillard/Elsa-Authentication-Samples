using Auth0.AspNetCore.Authentication;
using Elsa.Studio.Contracts;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Elsa.Studio.Login.Contracts;
using Elsa.Studio.Login.BlazorServer.Services;
using Elsa.Studio;
using Blazored.LocalStorage;
using System.Security.Claims;
using Elsa.Identity.Options;
using FastEndpoints;

namespace ElsaStudio.Auth0LoginModule
{
    public static class ServiceCollectionsExtensions
    {
        public static IServiceCollection AddIdentityServer(this IServiceCollection services, Action<IdentityTokenOptions> identityTokenOptions)
        {
            services.Configure(identityTokenOptions);
            return services;
        }
        public static IServiceCollection AddAuth0LoginModule(this IServiceCollection services, IConfiguration configuration)
        {
            // Register HttpContextAccessor.
            services.AddHttpContextAccessor();

            // Register Blazored LocalStorage.
            services.AddBlazoredLocalStorage();

            services.AddScoped<IFeature, Feature>();
            services.AddScoped<IJwtAccessor, BlazorServerJwtAccessor>();
            services.AddScoped<IAccessTokenIssuer, DefaultAccessTokenIssuer>();
            services.AddSingleton<TimeProvider>(TimeProvider.System);
            services.AddFastEndpoints();

            //Register this to be able to use the Helpers to create JWT available in FastEndpoint Libraries.
            Factory.RegisterTestServices((_) => { });

            services
                .AddAuth0WebAppAuthentication(options => {
                    options.Domain = configuration["Auth0:Domain"];
                    options.ClientId = configuration["Auth0:ClientId"];
                    options.ClientSecret = configuration["Auth0:ClientSecret"];
                    options.Scope = "openid profile email";
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
                })
                //Use This to use the Access token of Auth0 , need to change the auth on the Api Server Side.
                //.WithAccessToken(options =>
                //{
                //    options.Audience = configuration["Auth0:Audience"];
                //}); 
            ;
            return services;
        }
        public static IEndpointRouteBuilder UseAuth0LoginPage(this IEndpointRouteBuilder app)   
        {

            app.MapGet("/Account/Login", async (HttpContext httpContext, string redirectUri = "/") =>
            {
                var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
                        .WithRedirectUri(redirectUri)
                        .Build();
                await httpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
            });

            app.MapGet("/Account/Logout", async (HttpContext httpContext, string redirectUri = "/") =>
            {
                var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
                        .WithRedirectUri(redirectUri)
                        .Build();

                await httpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
                await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            });

            return app;
        }
    }
}
