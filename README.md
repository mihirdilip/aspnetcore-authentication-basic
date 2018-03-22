# Mihir.AspNetCore.Authentication.Basic
Basic Scheme Authentication Implementation for ASP.NET Core 2.0

Setting it up is quite simple. You will need basic working knowledge of ASP.NET Core 2.0 to get started using this code.


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
			// write your implementation here..
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
 
 

__References__
- [Creating an authentication scheme in ASP.NET Core 2.0](https://joonasw.net/view/creating-auth-scheme-in-aspnet-core-2)
- [aspnet/Security](https://github.com/aspnet/Security)
- [ASP.NET Core Security documentation](https://docs.microsoft.com/en-us/aspnet/core/security)
- [RFC 7617: Technical spec for HTTP Basic](https://tools.ietf.org/html/rfc7617)
