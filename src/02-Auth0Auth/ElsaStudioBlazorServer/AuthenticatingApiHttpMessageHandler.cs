using Elsa.Studio.Contracts;
using Elsa.Studio.Login.Contracts;
using Elsa.Studio;
using System.Net.Http.Headers;
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