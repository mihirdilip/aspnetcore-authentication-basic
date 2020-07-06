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

namespace AspNetCore.Authentication.Basic
{
    /// <summary>
    /// Inherited from <see cref="AuthenticationHandler{TOptions}"/> for basic authentication.
    /// </summary>
    internal class BasicHandler : AuthenticationHandler<BasicOptions>
	{
		private readonly IBasicUserValidationService _basicUserValidationService;

		/// <summary>
		/// Basic Handler Constructor.
		/// </summary>
		/// <param name="options"></param>
		/// <param name="logger"></param>
		/// <param name="encoder"></param>
		/// <param name="clock"></param>
		/// <param name="basicUserValidationService"></param>
		public BasicHandler(IOptionsMonitor<BasicOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, IBasicUserValidationService basicUserValidationService) 
			: base(options, logger, encoder, clock)
		{
			_basicUserValidationService = basicUserValidationService ?? throw new ArgumentNullException(nameof(basicUserValidationService));
		}

		private string Challenge => $"{BasicDefaults.AuthenticationScheme} realm=\"{Options.Realm}\", charset=\"UTF-8\"";

		/// <summary>
		/// Get or set <see cref="BasicEvents"/>.
		/// </summary>
        protected new BasicEvents Events { get => (BasicEvents)base.Events; set => base.Events = value; }

		/// <summary>
		/// Create an instance of <see cref="BasicEvents"/>.
		/// </summary>
		/// <returns></returns>
		protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new BasicEvents());

		/// <summary>
		/// Searches the 'Authorization' header for 'Basic' scheme with base64 encoded username:password string value of which is validated using implementation of <see cref="IBasicUserValidationService"/> passed as type parameter when setting up basic authentication in the Startup.cs 
		/// </summary>
		/// <returns><see cref="AuthenticateResult"/></returns>
		protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
		{
			if (!Request.Headers.ContainsKey(HeaderNames.Authorization))
			{
				Logger.LogInformation("No 'Authorization' header found in the request.");
				return AuthenticateResult.NoResult();
			}

			if (!AuthenticationHeaderValue.TryParse(Request.Headers[HeaderNames.Authorization], out var headerValue))
			{
				Logger.LogInformation("No valid 'Authorization' header found in the request.");
				return AuthenticateResult.NoResult();
			}
			
			if (!headerValue.Scheme.Equals(BasicDefaults.AuthenticationScheme, StringComparison.OrdinalIgnoreCase))
			{
				Logger.LogInformation($"'Authorization' header found but the scheme is not a '{BasicDefaults.AuthenticationScheme}' scheme.");
				return AuthenticateResult.NoResult();
			}

			BasicCredentials credentials;
            try
            {
				credentials = DecodeBasicCredentials(headerValue.Parameter);
			}
            catch (Exception exception)
            {
				return AuthenticateResult.Fail(exception);
            }
            
			try
			{
				// Raise validate credentials event.
				// It can either have a result set or a principal set or just a bool? validation result set.
				var validateCredentialsContext = new BasicValidateCredentialsContext(Context, Scheme, Options, credentials.Username, credentials.Password);
				await Events.ValidateCredentialsAsync(validateCredentialsContext).ConfigureAwait(false);
				
				if (validateCredentialsContext.Result != null)
                {
					return validateCredentialsContext.Result;
                }
				
				if (validateCredentialsContext.Principal?.Identity != null && validateCredentialsContext.Principal.Identity.IsAuthenticated)
				{
					// If claims principal is set and is authenticated then build a ticket by calling and return success.
					validateCredentialsContext.Success();
					return validateCredentialsContext.Result;
				}

				var hasValidationSucceeded = false;
				var validationFailureMessage = "Invalid username or password.";

				if (validateCredentialsContext.ValidationResult.HasValue)
                {
					hasValidationSucceeded = validateCredentialsContext.ValidationResult.Value;

					// If validation result was not successful return failure.
					if (!hasValidationSucceeded)
					{
						return AuthenticateResult.Fail(
							validateCredentialsContext.ValidationFailureException ?? new Exception(validationFailureMessage)
						);
					}
				}

				// If validation result was not set then validate using the implementation of IBasicUserValidationService.
				if (!hasValidationSucceeded)
                {
					if (_basicUserValidationService is DefaultBasicUserValidationService)
                    {
						throw new InvalidOperationException($"Either {nameof(Options.Events.OnValidateCredentials)} delegate on configure options {nameof(Options.Events)} should be set or an implementaion of {nameof(IBasicUserValidationService)} should be registered in the dependency container.");
                    }
					hasValidationSucceeded = await _basicUserValidationService.IsValidAsync(credentials.Username, credentials.Password);
				}

				// Return fail if validation not succeeded.
				if (!hasValidationSucceeded)
				{
					return AuthenticateResult.Fail(validationFailureMessage);
				}

				// Create claims principal.
				var claims = new[] 
				{
					new Claim(ClaimTypes.NameIdentifier, credentials.Username, ClaimValueTypes.String, ClaimsIssuer),
					new Claim(ClaimTypes.Name, credentials.Username, ClaimValueTypes.String, ClaimsIssuer)					
				};
				var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name));
				
				// Raise authentication succeeded event.
				var authenticationSucceededContext = new BasicAuthenticationSucceededContext(Context, Scheme, Options, principal);
				await Events.AuthenticationSucceededAsync(authenticationSucceededContext).ConfigureAwait(false);
				
				if (authenticationSucceededContext.Result != null)
                {
					return authenticationSucceededContext.Result;
                }

				if (authenticationSucceededContext.Principal?.Identity != null && authenticationSucceededContext.Principal.Identity.IsAuthenticated)
				{
					// If claims principal is set and is authenticated then build a ticket by calling and return success.
					authenticationSucceededContext.Success();
					return authenticationSucceededContext.Result;
				}

				return AuthenticateResult.Fail("No authenticated prinicipal set.");
			}
            catch (Exception exception)
            {
				var authenticationFailedContext = new BasicAuthenticationFailedContext(Context, Scheme, Options, exception);
				await Events.AuthenticationFailedAsync(authenticationFailedContext).ConfigureAwait(false);
				
				if (authenticationFailedContext.Result != null)
				{
					return authenticationFailedContext.Result;
				}
				
				throw;
			}
		}

		/// <inheritdoc/>
        protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
			// Raise handle forbidden event.
			var handleForbiddenContext = new BasicHandleForbiddenContext(Context, Scheme, Options, properties);
			await Events.HandleForbiddenAsync(handleForbiddenContext).ConfigureAwait(false);
			if (handleForbiddenContext.IsHandled)
			{
				return;
			}

			await base.HandleForbiddenAsync(properties);
        }

		/// <summary>
		/// Handles the un-authenticated requests. 
		/// Returns 401 status code in response.
		/// If <see cref="BasicOptions.SuppressWWWAuthenticateHeader"/> is not set then,
		/// adds 'WWW-Authenticate' response header with 'Basic' authentication scheme and 'Realm' 
		/// to let the client know that 'Basic' authentication scheme is being used by the system.
		/// </summary>
		/// <param name="properties"><see cref="AuthenticationProperties"/></param>
		/// <returns>A Task.</returns>
		protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
		{
			// Raise handle challenge event.
			var handleChallengeContext = new BasicHandleChallengeContext(Context, Scheme, Options, properties);
			await Events.HandleChallengeAsync(handleChallengeContext).ConfigureAwait(false);
			if (handleChallengeContext.IsHandled)
			{
				return;
			}

			if (!Options.SuppressWWWAuthenticateHeader)
			{
				Response.Headers[HeaderNames.WWWAuthenticate] = Challenge;
			}
			await base.HandleChallengeAsync(properties);
		}

		private BasicCredentials DecodeBasicCredentials(string credentials)
        {
			string username;
			string password;
			try
			{
				// Convert the base64 encoded 'username:password' to normal string and parse username and password from colon(:) separated string.
				var usernameAndPassword = Encoding.UTF8.GetString(Convert.FromBase64String(credentials));
				var usernameAndPasswordSplit = usernameAndPassword.Split(':');
				if (usernameAndPasswordSplit.Length != 2)
				{
					throw new Exception("Invalid Basic authentication header.");
				}
				username = usernameAndPasswordSplit[0];
				password = usernameAndPasswordSplit[1];
			}
			catch (Exception)
			{
				throw new Exception($"Problem decoding '{BasicDefaults.AuthenticationScheme}' scheme credentials.");
			}

			if (string.IsNullOrWhiteSpace(username))
			{
				throw new Exception("Username cannot be empty.");
			}
			
			if (password == null)
			{
				password = string.Empty;
			}
			
			return new BasicCredentials(username, password);
		}

		private struct BasicCredentials
        {
            public BasicCredentials(string username, string password)
            {
                Username = username;
                Password = password;
            }

            public string Username { get; }
            public string Password { get; }
        }
	}
}
