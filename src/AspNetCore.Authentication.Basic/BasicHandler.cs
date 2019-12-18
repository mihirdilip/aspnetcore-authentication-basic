// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Mihir.AspNetCore.Authentication.Basic
{
	/// <summary>
	/// Inherited from <see cref="AuthenticationHandler{TOptions}"/> for basic authentication.
	/// </summary>
	[Obsolete("This NuGet package has been made obsolete and moved to a new package named 'AspNetCore.Authentication.Basic'. Please consider removing this package and download the new one as there will be no future updates on this package. Sorry for the inconvenience caused. This was done purely for the naming of the package. New package name is 'AspNetCore.Authentication.Basic' which can be downloaded using NuGet Package Manager or from https://www.nuget.org/packages/AspNetCore.Authentication.Basic.")]
	public class BasicHandler : AuthenticationHandler<BasicOptions>
	{
		private readonly IBasicUserValidationService _basicUserValidationService;

		public BasicHandler(IOptionsMonitor<BasicOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, IBasicUserValidationService basicUserValidationService) 
			: base(options, logger, encoder, clock)
		{
			_basicUserValidationService = basicUserValidationService;
		}

		private string Challenge => $"{BasicDefaults.AuthenticationScheme} realm=\"{Options.Realm}\", charset=\"UTF-8\"";

		//protected new BasicEvents Events { get => (BasicEvents)base.Events; set => base.Events = value; }
		//protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new BasicEvents());

		/// <summary>
		/// Searches the 'Authorization' header for 'Basic' scheme with base64 encoded username:password string value of which is validated using implementation of <see cref="IBasicUserValidationService"/> passed as type parameter when setting up basic authentication in the Startup.cs 
		/// </summary>
		/// <returns></returns>
		protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
		{
			if (!Request.Headers.ContainsKey(HeaderNames.Authorization))
			{
				// No 'Authorization' header found in the request.
				return AuthenticateResult.NoResult();
			}

			if (!AuthenticationHeaderValue.TryParse(Request.Headers[HeaderNames.Authorization], out var headerValue))
			{
				// No valid 'Authorization' header found in the request.
				return AuthenticateResult.NoResult();
			}

			
			if (!headerValue.Scheme.Equals(BasicDefaults.AuthenticationScheme, StringComparison.OrdinalIgnoreCase))
			{
				// 'Authorization' header found but the scheme is not a basic scheme.
				return AuthenticateResult.NoResult();
			}

			// Convert the base64 encoded 'username:password' to normal string and parse username and password from colon(:) separated string.
			var usernameAndPassword = Encoding.UTF8.GetString(Convert.FromBase64String(headerValue.Parameter));
			var usernameAndPasswordSplit = usernameAndPassword.Split(':');
			if (usernameAndPasswordSplit.Length != 2)
			{
				return AuthenticateResult.Fail("Invalid Basic authentication header");
			}
			var username = usernameAndPasswordSplit[0];
			var password = usernameAndPasswordSplit[1];

			// Validate username and password by using the implementation of IBasicUserValidationService.
			var isValidUser = await _basicUserValidationService.IsValidAsync(username, password);
			if (!isValidUser)
			{
				return AuthenticateResult.Fail("Invalid username or password");
			}

			// Create 'AuthenticationTicket' and return as success if the above validation was successful.
			var claims = new[] { new Claim(ClaimTypes.Name, username) };
			var identity = new ClaimsIdentity(claims, Scheme.Name);
			var principal = new ClaimsPrincipal(identity);
			var ticket = new AuthenticationTicket(principal, Scheme.Name);
			return AuthenticateResult.Success(ticket);
		}

		/// <summary>
		/// Handles the un-authenticated requests. 
		/// Returns 401 status code in response.
		/// Adds 'WWW-Authenticate' with 'Basic' authentication scheme and 'Realm' in the response header 
		/// to let the client know that 'Basic' authentication scheme is being used by the system.
		/// </summary>
		/// <param name="properties"></param>
		/// <returns></returns>
		protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
		{
			Response.Headers[HeaderNames.WWWAuthenticate] = Challenge;
			await base.HandleChallengeAsync(properties);
		}
	}
}
