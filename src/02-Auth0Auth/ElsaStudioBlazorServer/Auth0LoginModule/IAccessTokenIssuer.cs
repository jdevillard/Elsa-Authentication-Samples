using Elsa.Identity.Models;
using Elsa.Identity.Options;
using FastEndpoints.Security;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace ElsaStudio.Auth0LoginModule
{
    public interface IAccessTokenIssuer
    {
        ValueTask<IssuedTokens> IssueTokensAsync(ClaimsIdentity userIdentity, string[] permissions, string[] roleNames, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Represents issued tokens.
    /// </summary>
    /// <param name="AccessToken">The access token.</param>
    /// <param name="RefreshToken">The refresh token.</param>
    public record IssuedTokens(string AccessToken, string RefreshToken);

    public class DefaultAccessTokenIssuer(IOptions<IdentityTokenOptions> identityTokenOptions, TimeProvider systemClock) : IAccessTokenIssuer
    {
        public async ValueTask<IssuedTokens> IssueTokensAsync(ClaimsIdentity userIdentity,  string[] permissions, string[] roleNames,  CancellationToken cancellationToken = default)
        {
            var tokenOptions = identityTokenOptions.Value;
            var signingKey = tokenOptions.SigningKey;
            var issuer = tokenOptions.Issuer;
            var audience = tokenOptions.Audience;
            var accessTokenLifetime = tokenOptions.AccessTokenLifetime;
            var refreshTokenLifetime = tokenOptions.RefreshTokenLifetime;

            if (string.IsNullOrWhiteSpace(signingKey)) throw new Exception("No signing key configured");
            if (string.IsNullOrWhiteSpace(issuer)) throw new Exception("No issuer configured");
            if (string.IsNullOrWhiteSpace(audience)) throw new Exception("No audience configured");

            var emailClaim = userIdentity?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email);
            
            var nameClaim = new Claim(JwtRegisteredClaimNames.Name, emailClaim.Value);
            var claims = new List<Claim>
            {
                nameClaim
            };

            var now = systemClock.GetUtcNow();
            var accessTokenExpiresAt = now.Add(accessTokenLifetime);
            var refreshTokenExpiresAt = now.Add(refreshTokenLifetime);
            var accessToken = JwtBearer.CreateToken(options => ConfigureTokenOptions(options, accessTokenExpiresAt.UtcDateTime));
            var refreshToken = JwtBearer.CreateToken(options => ConfigureTokenOptions(options, refreshTokenExpiresAt.UtcDateTime));

            return new IssuedTokens(accessToken, refreshToken);

            void ConfigureTokenOptions(JwtCreationOptions options, DateTime expireAt)
            {
                options.SigningKey = signingKey;
                options.ExpireAt = expireAt;
                options.Issuer = issuer;
                options.Audience = audience;
                options.User.Claims.AddRange(claims);
                options.User.Permissions.AddRange(permissions);
                options.User.Roles.AddRange(roleNames);
            }
        }
    }
}
