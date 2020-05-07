# AspNetCore.Authentication.Basic
Easy to use and very light weight Microsoft style Basic Scheme Authentication Implementation for ASP.NET Core.

[View On GitHub](https://github.com/mihirdilip/aspnetcore-authentication-basic)

## Installing
This library is published on NuGet. So the NuGet package can be installed directly to your project if you wish to use it without making any custom changes to the code.

Download directly from below link. Please consider downloading the new package as the old one has been made obsolete.  
New Package link - [AspNetCore.Authentication.Basic](https://www.nuget.org/packages/AspNetCore.Authentication.Basic).  
Old Package link - [Mihir.AspNetCore.Authentication.Basic](https://www.nuget.org/packages/Mihir.AspNetCore.Authentication.Basic).  

Or by running the below command on your project.

```
PM> Install-Package AspNetCore.Authentication.Basic
```

## Example Usage

Setting it up is quite simple. You will need basic working knowledge of ASP.NET Core 2.2 or newer to get started using this code.

On [**Startup.cs**](#startupcs), as shown below, add 2 lines in *ConfigureServices* method `services.AddAuthentication(BasicDefaults.AuthenticationScheme).AddBasic<BasicUserValidationService>(options => { options.Realm = "My App"; });`. And a line `app.UseAuthentication();` in *Configure* method.

Also add an implementation of *IBasicUserValidationService* as shown below in [**BasicUserValidationService.cs**](#basicuservalidationservicecs).

**NOTE: Always use HTTPS (SSL Certificate) protocol in production when using Basic authentication.**

#### Startup.cs (ASP.NET Core 3.0 or newer)

```C#
using AspNetCore.Authentication.Basic;
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

		services.AddControllers();

		//// By default, authentication is not challenged for every request which is ASP.NET Core's default intended behaviour.
		//// So to challenge authentication for every requests please use below option instead of above services.AddControllers().
		//services.AddControllers(options => 
		//{
		//	options.Filters.Add(new AuthorizeFilter(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()));
		//});
	}

	public void Configure(IApplicationBuilder app, IHostingEnvironment env)
	{
		app.UseHttpsRedirection();

		// The below order of pipeline chain is important!
		app.UseRouting();

		app.UseAuthentication();
		app.UseAuthorization();

		app.UseEndpoints(endpoints =>
		{
			endpoints.MapControllers();
		});
	}
}
```

#### Startup.cs (ASP.NET Core 2.2)

```C#
using AspNetCore.Authentication.Basic;
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

		//// By default, authentication is not challenged for every request which is ASP.NET Core's default intended behaviour.
		//// So to challenge authentication for every requests please use below option instead of above services.AddMvc().
		//services.AddMvc(options => 
		//{
		//	options.Filters.Add(new AuthorizeFilter(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()));
		//});
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
using AspNetCore.Authentication.Basic;
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
 
## Additional Notes
Please note that, by default, with ASP.NET Core, all the requests are not challenged for authentication. So don't worry if your *BasicUserValidationService* is not hit when you don't pass the required basic authentication details with the request. It is a normal behaviour. ASP.NET Core challenges authentication only when it is specifically told to do so either by decorating controller/method with *[Authorize]* filter attribute or by some other means. 

However, if you want all the requests to challenge authentication by default, depending on what you are using, you can add the below options line to *ConfigureServices* method on *Startup* class.

```C#
services.AddControllers(options => 
{ 
    options.Filters.Add(new AuthorizeFilter(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()));
});

// OR

services.AddMvc(options => 
{
    options.Filters.Add(new AuthorizeFilter(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()));
});
```
  
If you are not using MVC but, using Endpoints on ASP.NET Core 3.0 or newer, you can add a chain method `.RequireAuthorization()` to the endpoint map under *Configure* method on *Startup* class as shown below.

```C#
app.UseEndpoints(endpoints =>
{
    endpoints.MapGet("/", async context =>
    {
        await context.Response.WriteAsync("Hello World!");
    }).RequireAuthorization();  // NOTE THIS HERE!!!! 
});
``` 

## References
- [Creating an authentication scheme in ASP.NET Core 2.0](https://joonasw.net/view/creating-auth-scheme-in-aspnet-core-2)
- [aspnet/Security](https://github.com/aspnet/Security)
- [ASP.NET Core Security documentation](https://docs.microsoft.com/en-us/aspnet/core/security)
- [RFC 7617: Technical spec for HTTP Basic](https://tools.ietf.org/html/rfc7617)

## License
[MIT License](https://github.com/mihirdilip/aspnetcore-authentication-basic/blob/master/LICENSE.txt)
