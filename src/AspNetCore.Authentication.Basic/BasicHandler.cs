// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System;
using System.Net.Http.Headers;
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
		/// <summary>
		/// Basic Handler Constructor.
		/// </summary>
		/// <param name="options"></param>
		/// <param name="logger"></param>
		/// <param name="encoder"></param>
		/// <param name="clock"></param>
		public BasicHandler(IOptionsMonitor<BasicOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) 
			: base(options, logger, encoder, clock)
		{
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
				Logger.LogError(exception, "Error decoding credentials from header value.");
				return AuthenticateResult.Fail("Error decoding credentials from header value." + Environment.NewLine + exception.Message);

			}
            
			try
			{
				var validateCredentialsResult = await RaiseAndHandleEventValidateCredentialsAsync(credentials).ConfigureAwait(false);
				if (validateCredentialsResult != null)
                {
					// If result is set then return it.
					return validateCredentialsResult;
                }

				// Validate using the implementation of IBasicUserValidationService.
				var hasValidationSucceeded = await ValidateUsingBasicUserValidationServiceAsync(credentials.Username, credentials.Password).ConfigureAwait(false);
				return hasValidationSucceeded
					? await RaiseAndHandleAuthenticationSucceededAsync(credentials).ConfigureAwait(false)
					: AuthenticateResult.Fail("Invalid username or password.");
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

		private async Task<AuthenticateResult> RaiseAndHandleEventValidateCredentialsAsync(BasicCredentials credentials)
        {
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

			return null;
		}

		private async Task<AuthenticateResult> RaiseAndHandleAuthenticationSucceededAsync(BasicCredentials credentials)
        {
			// ..create claims principal.
			var principal = BasicUtils.BuildClaimsPrincipal(credentials.Username, Scheme.Name, ClaimsIssuer);

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

			Logger.LogError("No authenticated prinicipal set.");
			return AuthenticateResult.Fail("No authenticated prinicipal set.");
		}

		private async Task<bool> ValidateUsingBasicUserValidationServiceAsync(string username, string password)
        {
			IBasicUserValidationService basicUserValidationService = null;
			if (Options.BasicUserValidationServiceType != null)
			{
				basicUserValidationService = ActivatorUtilities.GetServiceOrCreateInstance(Context.RequestServices, Options.BasicUserValidationServiceType) as IBasicUserValidationService;
			}

			if (basicUserValidationService == null)
			{
				throw new InvalidOperationException($"Either {nameof(Options.Events.OnValidateCredentials)} delegate on configure options {nameof(Options.Events)} should be set or use an extention method with type parameter of type {nameof(IBasicUserValidationService)}.");
			}

			try
			{
				return await basicUserValidationService.IsValidAsync(username, password).ConfigureAwait(false);
			}
			finally
			{
				if (basicUserValidationService is IDisposable disposableBasicUserValidationService)
				{
					disposableBasicUserValidationService.Dispose();
				}
			}
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
