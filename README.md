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

Samples are available under [samples directory](samples).

Setting it up is quite simple. You will need basic working knowledge of ASP.NET Core 2.2 or newer to get started using this code.

On [**Startup.cs**](#startupcs), as shown below, add 2 lines in *ConfigureServices* method `services.AddAuthentication(BasicDefaults.AuthenticationScheme).AddBasic<BasicUserValidationService>(options => { options.Realm = "My App"; });`. And a line `app.UseAuthentication();` in *Configure* method.

Also add an implementation of *IBasicUserValidationService* as shown below in [**BasicUserValidationService.cs**](#basicuservalidationservicecs).

**NOTE: Always use HTTPS (SSL Certificate) protocol in production when using Basic authentication.**

#### Startup.cs (ASP.NET Core 3.0 or newer)

```C#
using AspNetCore.Authentication.Basic;
public class Startup
{
	public void ConfigureServices(IServiceCollection services)
	{
		// Add the Basic scheme authentication here..
        // It requires Realm to be set in the options if SuppressWWWAuthenticateHeader is not set.
        // If an implementation of IBasicUserValidationService interface is registered in the dependency register as well as OnValidateCredentials delegete on options.Events is also set then this delegate will be used instead of an implementation of IBasicUserValidationService.
        services.AddAuthentication(BasicDefaults.AuthenticationScheme)

            // The below AddBasic without type parameter will require OnValidateCredentials delegete on options.Events to be set unless an implementation of IBasicUserValidationService interface is registered in the dependency register.
            // Please note if both the delgate and validation server are set then the delegate will be used instead of BasicUserValidationService.
            //.AddBasic(options => { options.Realm = "My App"; });

            // The below AddBasic with type parameter will add the BasicUserValidationService to the dependency register. 
            // Please note if OnValidateCredentials delegete on options.Events is also set then this delegate will be used instead of BasicUserValidationService.
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
	public void ConfigureServices(IServiceCollection services)
	{
		// Add the Basic scheme authentication here..
        // It requires Realm to be set in the options if SuppressWWWAuthenticateHeader is not set.
        // If an implementation of IBasicUserValidationService interface is registered in the dependency register as well as OnValidateCredentials delegete on options.Events is also set then this delegate will be used instead of an implementation of IBasicUserValidationService.
        services.AddAuthentication(BasicDefaults.AuthenticationScheme)

            // The below AddBasic without type parameter will require OnValidateCredentials delegete on options.Events to be set unless an implementation of IBasicUserValidationService interface is registered in the dependency register.
            // Please note if both the delgate and validation server are set then the delegate will be used instead of BasicUserValidationService.
            //.AddBasic(options => { options.Realm = "My App"; });

            // The below AddBasic with type parameter will add the BasicUserValidationService to the dependency register. 
            // Please note if OnValidateCredentials delegete on options.Events is also set then this delegate will be used instead of BasicUserValidationService.
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

## Configuration (BasicOptions)
#### Realm
Required to be set if SuppressWWWAuthenticateHeader is not set to true. It is used with WWW-Authenticate response header when challenging un-authenticated requests.  
   
#### SuppressWWWAuthenticateHeader
Default value is false.  
When set to true, it will NOT return WWW-Authenticate response header when challenging un-authenticated requests.  
When set to false, it will return WWW-Authenticate response header when challenging un-authenticated requests.

#### Events
The object provided by the application to process events raised by the basic authentication middleware.  
The application may implement the interface fully, or it may create an instance of BasicEvents and assign delegates only to the events it wants to process.
- ##### OnValidateCredentials
	A delegate assigned to this property will be invoked just before validating credentials.  
	You must provide a delegate for this property for authentication to occur.  
	In your delegate you should either call context.ValidationSucceeded() which will handle construction of authentication principal from the user details which will be assiged the context.Principal property and call context.Success(), or construct an authentication principal from the user details & attach it to the context.Principal property and finally call context.Success() method.  
	If only context.Principal property set without calling context.Success() method then, Success() method is automaticalled called.

- ##### OnAuthenticationSucceeded  
	A delegate assigned to this property will be invoked when the authentication succeeds. It will not be called if OnValidateCredentials delegate is assigned.  
    It can be used for adding claims, headers, etc to the response.

- ##### OnAuthenticationFailed  
	A delegate assigned to this property will be invoked when the authentication fails.

- ##### OnHandleChallenge  
	A delegate assigned to this property will be invoked before a challenge is sent back to the caller when handling unauthorized response.  
	Only use this if you know what you are doing and if you want to use custom implementation.  Set the delegate to deal with 401 challenge concerns, if an authentication scheme in question deals an authentication interaction as part of it's request flow. (like adding a response header, or changing the 401 result to 302 of a login page or external sign-in location.)  
    Call context.Handled() at the end so that any default logic for this challenge will be skipped.

- ##### OnHandleForbidden  
	A delegate assigned to this property will be invoked if Authorization fails and results in a Forbidden response.  
	Only use this if you know what you are doing and if you want to use custom implementation.  
	Set the delegate to handle Forbid.  
	Call context.Handled() at the end so that any default logic will be skipped.


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
- [RFC 7617: Technical spec for HTTP Basic](https://tools.ietf.org/html/rfc7617)
- [ASP.NET Core Security documentation](https://docs.microsoft.com/en-us/aspnet/core/security)
- [aspnet/Security](https://github.com/dotnet/aspnetcore/tree/master/src/Security)

## License
[MIT License](https://github.com/mihirdilip/aspnetcore-authentication-basic/blob/master/LICENSE.txt)