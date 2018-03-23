# Mihir.AspNetCore.Authentication.Basic
Basic Scheme Authentication Implementation for ASP.NET Core 2.0

## Installing
This library is published on NuGet. So the NuGet package can be installed directly to your project if you wish to use it without making any custom changes to the code.

Download directly from [Mihir.AspNetCore.Authentication.Basic](https://www.nuget.org/packages/Mihir.AspNetCore.Authentication.Basic).

Or by running the below command on your project.

```
PM> Install-Package Mihir.AspNetCore.Authentication.Basic
```

## Example Usage

Setting it up is quite simple. You will need basic working knowledge of ASP.NET Core 2.0 to get started using this code.

On [**Startup.cs**](#startupcs), as shown below, add 2 lines in *ConfigureServices* method `services.AddAuthentication(BasicDefaults.AuthenticationScheme).AddBasic<BasicUserValidationService>(options => { options.Realm = "My App"; });`. And a line `app.UseAuthentication();` in *Configure* method.

Also add an implementation of *IBasicUserValidationService* as shown below in [**BasicUserValidationService.cs**](#basicuservalidationservicecs).

#### Startup.cs

```C#
using Mihir.AspNetCore.Authentication.Basic;
public class Startup
{
	public Startup(IConfiguration configuration)
	{
		Configuration = configuration;
	}

	public IConfiguration Configuration { get; }

	public void ConfigureServices(IServiceCollection services)
	{
		// Add the Basic scheme authentication here..
		// AddBasic extension takes an implementation of IBasicUserValidationService for validating the username and password. 
		// It also requires Realm to be set in the options.
		services.AddAuthentication(BasicDefaults.AuthenticationScheme)
			.AddBasic<BasicUserValidationService>(options => { options.Realm = "My App"; });

		services.AddMvc();
	}

	public void Configure(IApplicationBuilder app, IHostingEnvironment env)
	{
		app.UseAuthentication();
		app.UseMvc();
	}
}
```

#### BasicUserValidationService.cs
```C#
using Mihir.AspNetCore.Authentication.Basic;
public class BasicUserValidationService : IBasicUserValidationService
{
	private readonly ILogger<BasicUserValidationService> _logger;
	
	public BasicUserValidationService(ILogger<BasicUserValidationService> logger)
	{
		_logger = logger;
	}

	public Task<bool> IsValidAsync(string username, string password)
	{
		try
		{
			// write your implementation here and return true or false depending on the validation..
			return Task.FromResult(true);
		}
		catch (Exception e)
		{
			_logger.LogError(e, e.Message);
			throw;
		}
	}
}
```
 
 

## References
- [Creating an authentication scheme in ASP.NET Core 2.0](https://joonasw.net/view/creating-auth-scheme-in-aspnet-core-2)
- [aspnet/Security](https://github.com/aspnet/Security)
- [ASP.NET Core Security documentation](https://docs.microsoft.com/en-us/aspnet/core/security)
- [RFC 7617: Technical spec for HTTP Basic](https://tools.ietf.org/html/rfc7617)

## License
[MIT License](LICENSE)
