using Microsoft.AspNetCore.Authentication;
using Elsa.Studio.Login.Contracts;
using Blazored.LocalStorage;

namespace ElsaStudio.Auth0LoginModule
{
    public class BlazorServerJwtAccessor : IJwtAccessor
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILocalStorageService _localStorageService;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlazorServerJwtAccessor"/> class.
        /// </summary>
        public BlazorServerJwtAccessor(IHttpContextAccessor httpContextAccessor, ILocalStorageService localStorageService)
        {
            _httpContextAccessor = httpContextAccessor;
            _localStorageService = localStorageService;
        }

        /// <inheritdoc />
        public async ValueTask<string?> ReadTokenAsync(string name)
        {
            var httpContext = _httpContextAccessor.HttpContext ??
                throw new InvalidOperationException("No HttpContext available from the IHttpContextAccessor!");

            var accessToken = await httpContext.GetTokenAsync(name) ??
                throw new InvalidOperationException("No access_token was saved");

            return accessToken;
        }

        /// <inheritdoc />
        public async ValueTask WriteTokenAsync(string name, string token)
        {
            throw new NotImplementedException();
        }

        private bool IsPrerendering() => _httpContextAccessor.HttpContext?.Response.HasStarted == false;
    }
}
