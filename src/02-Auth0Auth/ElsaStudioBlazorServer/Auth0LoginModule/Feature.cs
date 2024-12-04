using Elsa.Studio.Abstractions;
using Elsa.Studio.Contracts;
using ElsaStudioBlazorServer.Auth0LoginModule;

namespace ElsaStudio.Auth0LoginModule
{
    public class Feature : FeatureBase
    {
        private readonly IAppBarService _appBarService;

        public Feature(IAppBarService appBarService)
        {
            _appBarService = appBarService;
            _appBarService.AddAppBarItem<AccessControl>();
        }

        public override ValueTask InitializeAsync(CancellationToken cancellationToken = default)
        {
            _appBarService.AddAppBarItem<AccessControl>();

            return ValueTask.CompletedTask;
        }

        
    }
}
