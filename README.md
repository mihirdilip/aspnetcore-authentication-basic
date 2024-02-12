# AspNetCore.Authentication.Basic
Easy to use and very light weight Microsoft style Basic Scheme Authentication Implementation for ASP.NET Core.

[View On GitHub](https://github.com/mihirdilip/aspnetcore-authentication-basic)

<br/>

## .NET (Core) Frameworks Supported  
.NET Framework 4.6.1 and/or NetStandard 2.0 onwards  
Multi targeted: net8.0; net7.0; net6.0; net5.0; netcoreapp3.1; netcoreapp3.0; netstandard2.0; net461

<br/> 

## Installing
This library is published on NuGet. So the NuGet package can be installed directly to your project if you wish to use it without making any custom changes to the code.

Download directly from below link. Please consider downloading the new package as the old one has been made obsolete.  
New Package link - [AspNetCore.Authentication.Basic](https://www.nuget.org/packages/AspNetCore.Authentication.Basic).  
Old Package link - [Mihir.AspNetCore.Authentication.Basic](https://www.nuget.org/packages/Mihir.AspNetCore.Authentication.Basic).  

Or by running the below command on your project.

```
PM> Install-Package AspNetCore.Authentication.Basic
```

<br/> 

## Example Usage

Samples are available under [samples directory](samples).

Setting it up is quite simple. You will need basic working knowledge of ASP.NET Core 2.0 or newer to get started using this library.

There are 2 different ways of using this library to do it's job. Both ways can be mixed if required.  
1] Using the implementation of *IBasicUserValidationService*  
2] Using *BasicOptions.Events* (OnValidateCredentials delegate) which is same approach you will find on Microsoft's authentication libraries

Notes:
- It requires Realm to be set in the options if SuppressWWWAuthenticateHeader is not set.
- If an implementation of IBasicUserValidationService interface is used as well as BasicOptions.Events.OnValidateCredentials delegate is also set then this delegate will be used first.

**Always use HTTPS (SSL Certificate) protocol in production when using basic authentication.**

#### Startup.cs (ASP.NET Core 3.0 onwards)

```C#
using AspNetCore.Authentication.Basic;
public class Startup
{
	public void ConfigureServices(IServiceCollection services)
	{
		// It requires Realm to be set in the options if SuppressWWWAuthenticateHeader is not set.
		// If an implementation of IBasicUserValidationService interface is used as well as options.Events.OnValidateCredentials delegate is also set then this delegate will be used first.
		
		services.AddAuthentication(BasicDefaults.AuthenticationScheme)

			// The below AddBasic without type parameter will require options.Events.OnValidateCredentials delegete to be set.
			//.AddBasic(options => { options.Realm = "My App"; });

			// The below AddBasic with type parameter will add the BasicUserValidationService to the dependency container. 
			.AddBasic<BasicUserValidationService>(options => { options.Realm = "My App"; });

		services.AddControllers();

		//// By default, authentication is not challenged for every request which is ASP.NET Core's default intended behaviour.
		//// So to challenge authentication for every requests please use below FallbackPolicy option.
		//services.AddAuthorization(options =>
		//{
		//	options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
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

#### Startup.cs (ASP.NET Core 2.0 onwards)

```C#
using AspNetCore.Authentication.Basic;
public class Startup
{
	public void ConfigureServices(IServiceCollection services)
	{
		// It requires Realm to be set in the options if SuppressWWWAuthenticateHeader is not set.
		// If an implementation of IBasicUserValidationService interface is used as well as options.Events.OnValidateCredentials delegate is also set then this delegate will be used first.

		services.AddAuthentication(BasicDefaults.AuthenticationScheme)

			// The below AddBasic without type parameter will require options.Events.OnValidateCredentials delegete to be set.
			//.AddBasic(options => { options.Realm = "My App"; });

			// The below AddBasic with type parameter will add the BasicUserValidationService to the dependency container. 
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
	private readonly IUserRepository _userRepository;

	public BasicUserValidationService(ILogger<BasicUserValidationService> logger, IUserRepository userRepository)
	{
		_logger = logger;
		_userRepository = userRepository;
	}

	public async Task<bool> IsValidAsync(string username, string password)
	{
		try
		{
			// NOTE: DO NOT USE THIS IMPLEMENTATION. THIS IS FOR DEMO PURPOSE ONLY
			// Write your implementation here and return true or false depending on the validation..
			var user = await _userRepository.GetUserByUsername(username);
			var isValid = user != null && user.Password == password;
			return isValid;
		}
		catch (Exception e)
		{
			_logger.LogError(e, e.Message);
			throw;
		}
	}
}
```

<br/>
<br/>

## Configuration (BasicOptions)

### Realm
Required to be set if SuppressWWWAuthenticateHeader is not set to true. It is used with WWW-Authenticate response header when challenging un-authenticated requests.  
   
### SuppressWWWAuthenticateHeader
Default value is false.  
If set to true, it will NOT return WWW-Authenticate response header when challenging un-authenticated requests.  
If set to false, it will return WWW-Authenticate response header when challenging un-authenticated requests.

### IgnoreAuthenticationIfAllowAnonymous (available on ASP.NET Core 3.0 onwards)
Default value is false.  
If set to true, it checks if AllowAnonymous filter on controller action or metadata on the endpoint which, if found, it does not try to authenticate the request.

### Events
The object provided by the application to process events raised by the basic authentication middleware.  
The application may implement the interface fully, or it may create an instance of BasicEvents and assign delegates only to the events it wants to process.
- #### OnValidateCredentials
	A delegate assigned to this property will be invoked just before validating credentials.  
	You must provide a delegate for this property for authentication to occur.  
	In your delegate you should either call context.ValidationSucceeded() which will handle construction of authentication claims principal from the user details which will be assiged the context.Principal property and calls context.Success(), or construct an authentication claims principal from the user details and assign it to the context.Principal property and finally call context.Success() method.  
	If only context.Principal property set without calling context.Success() method then, Success() method is automaticalled called.

- #### OnAuthenticationSucceeded  
	A delegate assigned to this property will be invoked when the authentication succeeds. It will not be called if OnValidateCredentials delegate is assigned.  
	It can be used for adding claims, headers, etc to the response.

- #### OnAuthenticationFailed  
	A delegate assigned to this property will be invoked when any unexpected exception is thrown within the library.

- #### OnHandleChallenge  
	A delegate assigned to this property will be invoked before a challenge is sent back to the caller when handling unauthorized response.  
	Only use this if you know what you are doing and if you want to use custom implementation.  Set the delegate to deal with 401 challenge concerns, if an authentication scheme in question deals an authentication interaction as part of it's request flow. (like adding a response header, or changing the 401 result to 302 of a login page or external sign-in location.)  
	Call context.Handled() at the end so that any default logic for this challenge will be skipped.

- #### OnHandleForbidden  
	A delegate assigned to this property will be invoked if Authorization fails and results in a Forbidden response.  
	Only use this if you know what you are doing and if you want to use custom implementation.  
	Set the delegate to handle Forbid.  
	Call context.Handled() at the end so that any default logic will be skipped.

<br/>
<br/>

## Additional Notes

### Basic Authentication Not Challenged
With ASP.NET Core, all the requests are not challenged for authentication by default. So don't worry if your *BasicUserValidationService* is not hit when you don't pass the required basic authentication details with the request. It is a normal behaviour. ASP.NET Core challenges authentication only when it is specifically told to do so either by decorating controller/method with *[Authorize]* filter attribute or by some other means. 

However, if you want all the requests to challenge authentication by default, depending on what you are using, you can add the below options line to *ConfigureServices* method on *Startup* class.

```C#
// On ASP.NET Core 3.0 onwards
services.AddAuthorization(options =>
{
	options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
});

// OR

// On ASP.NET Core 2.0 onwards
services.AddMvc(options => 
{
	options.Filters.Add(new AuthorizeFilter(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()));
});
```
  
If you are not using MVC but, using Endpoints on ASP.NET Core 3.0 or newer, you can add a chain method `.RequireAuthorization()` to the endpoint map under *Configure* method on *Startup* class as shown below.

```C#
// ASP.NET Core 3.0 onwards
app.UseEndpoints(endpoints =>
{
	endpoints.MapGet("/", async context =>
	{
		await context.Response.WriteAsync("Hello World!");
	}).RequireAuthorization();  // NOTE THIS HERE!!!! 
});
``` 

### Multiple Authentication Schemes
ASP.NET Core supports adding multiple authentication schemes which this library also supports. Just need to use the extension method which takes scheme name as parameter. The rest is all same. This can be achieved in many different ways. Below is just a quick rough example.   

Please note that scheme name parameter can be any string you want.

```C#
public void ConfigureServices(IServiceCollection services)
{
	services.AddTransient<IUserRepository, InMemoryUserRepository>();
		
	services.AddAuthentication("Scheme1")

		.AddBasic<BasicUserValidationService>("Scheme1", options => { options.Realm = "My App"; })

		.AddBasic<BasicUserValidationService_2>("Scheme2", options => { options.Realm = "My App"; })
		
		.AddBasic("Scheme3", options => 
		{ 
			options.Realm = "My App"; 
			options.Events = new BasicEvents
			{
				OnValidateCredentials = async (context) =>
				{
					var userRepository = context.HttpContext.RequestServices.GetRequiredService<IUserRepository>();
					var user = await userRepository.GetUserByUsername(context.Username);
					var isValid = user != null && user.Password == context.Password;
					if (isValid)
					{
						context.Response.Headers.Add("ValidationCustomHeader", "From OnValidateCredentials");
						var claims = new[]
						{
							new Claim("CustomClaimType", "Custom Claim Value - from OnValidateCredentials")
						};
						context.ValidationSucceeded(claims);    // claims are optional
					}
					else
					{
						context.ValidationFailed();
					}
				}
			}
		});

	services.AddControllers();

	services.AddAuthorization(options =>
	{
		options.FallbackPolicy = new AuthorizationPolicyBuilder("Scheme1", "Scheme2", "Scheme3").RequireAuthenticatedUser().Build();
	});
}
```

<br/>
<br/>

## Release Notes
| Version | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Notes |
|---------|-------|
|8.0.0    | <ul><li>net8.0 support added</li><li>Sample project for net8.0 added</li><li>BasicSamplesClient.http file added for testing sample projects</li><li>Readme updated</li></ul> |
|7.0.0    | <ul><li>net7.0 support added</li><li>Information log on handler is changed to Debug log when Authorization header is not found on the request</li><li>Added package validations</li><li>Sample project for net7.0 added</li><li>Readme updated</li><li>Readme added to package</li></ul> |
|6.0.1    | <ul><li>net6.0 support added</li><li>Information log on handler is changed to Debug log when IgnoreAuthenticationIfAllowAnonymous is enabled [#9](https://github.com/mihirdilip/aspnetcore-authentication-basic/issues/9)</li><li>Sample project added</li><li>Readme updated</li><li>Copyright year updated on License</li></ul> |
|5.1.0    | <ul><li>Visibility of the handler changed to public</li><li>Tests added</li><li>Readme updated</li><li>Copyright year updated on License</li></ul> |
|5.0.0    | <ul><li>Net 5.0 target framework added</li><li>IgnoreAuthenticationIfAllowAnonymous added to the BasicOptions from netcoreapp3.0 onwards</li></ul> |
|3.1.1    | <ul><li>Fixed issue with resolving of IBasicUserValidationService implementation when using multiple schemes</li></ul> |
|3.1.0    | <ul><li>Multitarget framework support added</li><li>Strong Name Key support added</li><li>Source Link support added</li><li>SuppressWWWAuthenticateHeader added to configure options</li><li>Events added to configure options</li></ul> |
|2.2.0    | <ul><li>Basic Authentication Implementation for ASP.NET Core</li></ul> |

<br/>
<br/>

## References
- [RFC 7617: Technical spec for HTTP Basic](https://tools.ietf.org/html/rfc7617)
- [ASP.NET Core Security documentation](https://docs.microsoft.com/en-us/aspnet/core/security)
- [aspnet/Security](https://github.com/dotnet/aspnetcore/tree/master/src/Security)

## License
[MIT License](https://github.com/mihirdilip/aspnetcore-authentication-basic/blob/master/LICENSE.txt)